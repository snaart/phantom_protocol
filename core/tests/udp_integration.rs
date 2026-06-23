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

/// ε / WIRE v5 (P3) — after the handshake the client stamps its rotating `CID_0`
/// (not the bootstrap ConnId), and the server's demux routes it because it
/// registered the inbound CID window `[CID_0 .. CID_K]`. The bidirectional
/// exchange only completes if `CID_0` routes (without the window the data misses
/// the demux and the exchange hangs); and the server's route table holds the
/// window (> 1 route) — a v4 session had only the single bootstrap route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_client_stamps_cid0_and_server_routes_the_window() {
    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    let listener_for_server = listener.clone();
    let server = tokio::spawn(async move {
        let session = listener_for_server
            .accept()
            .await
            .expect("accept")
            .session();
        let msg = session.recv().await.expect("server recv");
        assert_eq!(msg, b"ping");
        session.send(b"pong".to_vec()).await.expect("server send");
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    let transport = UdpClientTransport::connect(addr)
        .await
        .expect("udp connect");
    let client = PhantomSession::connect_with_transport(&addr.to_string(), transport, key);
    client.send(b"ping".to_vec()).await.expect("client send");
    // The reply only arrives if the client's post-handshake CID_0 datagrams routed
    // — i.e. the server registered the rotating-CID window. Without it, CID_0 misses
    // the demux and this would time out.
    let reply = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("client recv");
    assert_eq!(reply, b"pong");

    // While the session is still alive (server task sleeping), the server's route
    // table holds the registered CID window in addition to the bootstrap ConnId.
    assert!(
        listener.active_route_count() > 1,
        "server must register the CID window (> 1 route); got {}",
        listener.active_route_count()
    );
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
            let s = listener.clone().accept().await.expect("accept").session();
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

/// ε / WIRE v5 (P4) — DIRECT on-wire proof that the routing CID rotates across a
/// migration. A relay records the ConnId of every post-handshake (OneRtt)
/// client->server datagram; after `migrate()` the client stamps a fresh `CID_1`,
/// so the relay observes >= 2 distinct post-handshake ConnIds — an on-path
/// observer cannot link the pre- and post-migration flows by their cleartext CID
/// (threat-model §12.5). The reliable stream resumes byte-exact through the
/// rotation, routed by the server's pre-registered inbound window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_cid_rotates_on_the_wire_across_migration() {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use tokio::net::UdpSocket;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();
    let server = tokio::spawn(async move {
        let s = listener.accept().await.expect("accept").session();
        // Round 0 only (pre-migration) — the client needs this echo. Post-migration
        // we assert only the on-wire CID, so the server just stays alive (keeping its
        // routes + window) while the client fires the rotated-CID datagrams.
        let m = s.recv().await.expect("recv");
        s.send(m).await.expect("echo");
        tokio::time::sleep(Duration::from_millis(800)).await;
    });

    // Relay (client <-> relay <-> server) that records the ConnId of each
    // post-handshake (OneRtt) client->server datagram. OneRtt = type bits `01` in
    // the envelope flags byte (`buf[0] >> 6 == 1`); the ConnId is `buf[1..9]`.
    let onertt_cids: Arc<Mutex<HashSet<[u8; 8]>>> = Arc::new(Mutex::new(HashSet::new()));
    // EPS-02: also record the server->client (s2c) OneRtt ConnIds, to assert the
    // RETURN direction rotates too (the server rotates its outbound CID when it
    // detects the client's migration — otherwise s2c stays linkable).
    let onertt_s2c_cids: Arc<Mutex<HashSet<[u8; 8]>>> = Arc::new(Mutex::new(HashSet::new()));
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upstream.connect(server_addr).await.unwrap();
    let cids = onertt_cids.clone();
    let s2c_cids = onertt_s2c_cids.clone();
    tokio::spawn(async move {
        let mut c2s = vec![0u8; 2048];
        let mut s2c = vec![0u8; 2048];
        let mut client_addr: Option<std::net::SocketAddr> = None;
        loop {
            tokio::select! {
                r = relay.recv_from(&mut c2s) => {
                    let (n, from) = r.unwrap();
                    client_addr = Some(from);
                    if n >= 9 && (c2s[0] >> 6) == 1 {
                        let mut cid = [0u8; 8];
                        cid.copy_from_slice(&c2s[1..9]);
                        cids.lock().unwrap().insert(cid);
                    }
                    upstream.send(&c2s[..n]).await.unwrap();
                }
                r = upstream.recv(&mut s2c) => {
                    let n = r.unwrap();
                    if n >= 9 && (s2c[0] >> 6) == 1 {
                        let mut cid = [0u8; 8];
                        cid.copy_from_slice(&s2c[1..9]);
                        s2c_cids.lock().unwrap().insert(cid);
                    }
                    if let Some(ca) = client_addr {
                        relay.send_to(&s2c[..n], ca).await.unwrap();
                    }
                }
            }
        }
    });

    let transport = UdpClientTransport::connect(relay_addr).await.unwrap();
    let client = PhantomSession::connect_with_transport(&relay_addr.to_string(), transport, key);

    // Round 0 (pre-migration): the data plane establishes on CID_0 (the relay
    // records it).
    client.send(b"r0".to_vec()).await.unwrap();
    let e0 = timeout(Duration::from_secs(10), client.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e0, b"r0");
    let before = onertt_cids.lock().unwrap().len();
    assert!(before >= 1, "at least CID_0 must be seen pre-migration");
    // EPS-02: the server echoed r0, so its s2c CID_0 is on the wire pre-migration.
    let s2c_before = onertt_s2c_cids.lock().unwrap().len();
    assert!(
        s2c_before >= 1,
        "at least the server's s2c CID_0 must be seen pre-migration"
    );

    // Migrate -> the client rotates its outbound CID to CID_1, then fire
    // post-migration datagrams. The rotated CID appears on the wire (the reliable
    // stream keeps retransmitting, so the relay observes CID_1 regardless of
    // consumption). The byte-exact stream survival across migration is covered by
    // udp_integration_migration_survives_mid_exchange; this test isolates the
    // on-wire CID rotation (the unlinkability property).
    client.migrate("127.0.0.1:0".to_string()).await.unwrap();
    for i in 1..4 {
        let _ = client.send(format!("r{i}").into_bytes()).await;
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The relay observed a fresh post-handshake ConnId after the migration: the
    // cleartext CID rotated to an independent-random value, so an on-path observer
    // cannot link the pre- and post-migration flows by it (threat-model §12.5).
    let after = onertt_cids.lock().unwrap().len();
    assert!(
        after >= 2 && after > before,
        "the on-wire c2s CID must rotate across migration (before {before}, after {after} distinct OneRtt CIDs)"
    );
    // EPS-02: the server, on detecting the client's migration (an authenticated
    // new path_id), rotates its OWN outbound CID — so the server->client direction
    // also shows a fresh ConnId (its post-migration ACKs carry CID_s2c(1)). Without
    // the symmetric-rotation fix this stays at 1 (the s2c CID was stable across the
    // client migration → linkable; threat-model §12.5 residual EPS-02).
    let s2c_after = onertt_s2c_cids.lock().unwrap().len();
    assert!(
        s2c_after >= 2 && s2c_after > s2c_before,
        "the on-wire s2c CID must ALSO rotate across a client migration (before {s2c_before}, after {s2c_after} distinct OneRtt CIDs) — EPS-02"
    );

    server.await.unwrap();
}

/// A2a (server migration, full) — the SERVER changes its send path mid-session via
/// `migrate_server`: it rebinds its send socket to a fresh local address (so its s2c
/// egresses a NEW source the peer hears) and rotates the s2c `path_id` + CID in lock-step.
/// A relay with an UNCONNECTED upstream socket (so it can hear the migrated server's new
/// source — mirroring the client's D1 unconnected socket) records that the s2c source
/// address AND **both** the s2c and c2s ConnIds rotate across the move, while the session
/// survives byte-exact in both directions (c2s keeps flowing through the listen-address
/// overlap). The c2s CID rotation is the EPS-02 closure for server-initiated migration: the
/// client reflects the server's migration (bumps its path_id + rotates its c2s CID), so a
/// both-networks observer cannot relink the session by EITHER direction's ConnId across a
/// server move.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_server_migration_rotates_both_cids_and_survives() {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use tokio::net::UdpSocket;

    const POST: usize = 4;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    // Server: warmup echo, then migrate its send path, then echo POST post-migration
    // rounds (so its rotated-CID s2c is observable AND we prove bidirectional survival).
    let server = tokio::spawn(async move {
        let s = listener.accept().await.expect("accept").session();
        let m = s.recv().await.expect("recv warmup");
        s.send(m).await.expect("echo warmup");
        // Server-side migration: rebind the send socket + rotate s2c path_id/CID.
        s.migrate_server("127.0.0.1:0".to_string())
            .await
            .expect("server migrate");
        for _ in 0..POST {
            let m = s.recv().await.expect("recv post");
            s.send(m).await.expect("echo post");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    // Relay (client <-> relay <-> server). The upstream socket is UNCONNECTED so it can
    // still receive s2c after the server moves to a new source (a connected socket would
    // drop it at the kernel — exactly the D1 fix, here on the relay standing in for the
    // client's view of the server). c2s is always forwarded to the established listen
    // address (the server keeps receiving there via the demux during the overlap).
    let s2c_cids: Arc<Mutex<HashSet<[u8; 8]>>> = Arc::new(Mutex::new(HashSet::new()));
    let s2c_srcs: Arc<Mutex<HashSet<std::net::SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
    let c2s_cids: Arc<Mutex<HashSet<[u8; 8]>>> = Arc::new(Mutex::new(HashSet::new()));
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let s2c_c = s2c_cids.clone();
    let s2c_s = s2c_srcs.clone();
    let c2s_c = c2s_cids.clone();
    tokio::spawn(async move {
        let mut c2s = vec![0u8; 2048];
        let mut s2c = vec![0u8; 2048];
        let mut client_addr: Option<std::net::SocketAddr> = None;
        loop {
            tokio::select! {
                r = relay.recv_from(&mut c2s) => {
                    let (n, from) = r.unwrap();
                    client_addr = Some(from);
                    if n >= 9 && (c2s[0] >> 6) == 1 {
                        let mut cid = [0u8; 8];
                        cid.copy_from_slice(&c2s[1..9]);
                        c2s_c.lock().unwrap().insert(cid);
                    }
                    upstream.send_to(&c2s[..n], server_addr).await.unwrap();
                }
                r = upstream.recv_from(&mut s2c) => {
                    let (n, src) = r.unwrap();
                    if n >= 9 && (s2c[0] >> 6) == 1 {
                        let mut cid = [0u8; 8];
                        cid.copy_from_slice(&s2c[1..9]);
                        s2c_c.lock().unwrap().insert(cid);
                        s2c_s.lock().unwrap().insert(src);
                    }
                    if let Some(ca) = client_addr {
                        relay.send_to(&s2c[..n], ca).await.unwrap();
                    }
                }
            }
        }
    });

    let transport = UdpClientTransport::connect(relay_addr).await.unwrap();
    let client = PhantomSession::connect_with_transport(&relay_addr.to_string(), transport, key);

    // Warmup: establishes the session on s2c CID_0 from the listen address.
    client.send(b"r0".to_vec()).await.unwrap();
    let e0 = timeout(Duration::from_secs(10), client.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e0, b"r0");

    // Post-migration: the server has rebound its send socket; each echo proves the c2s
    // still reaches the listen address (demux overlap) AND the rotated-source/rotated-CID
    // s2c reaches us — byte-exact, no re-handshake.
    for i in 0..POST {
        let msg = format!("p{i}").into_bytes();
        client.send(msg.clone()).await.unwrap();
        let echo = timeout(Duration::from_secs(10), client.recv())
            .await
            .expect("no timeout through the server migration")
            .expect("recv post-migration echo");
        assert_eq!(
            echo, msg,
            "byte-exact bidirectional flow survives server migration"
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The server sent s2c from the listen address (warmup) AND from the migrated socket
    // (post-migration) — two distinct sources, impossible without a real send-socket
    // rebind — and rotated its CID across the move. A no-op `migrate_server` would leave
    // both at 1 source / would not change the source set.
    let s2c_srcs_seen = s2c_srcs.lock().unwrap();
    assert!(
        s2c_srcs_seen.contains(&server_addr),
        "the server's pre-migration s2c must come from the listen address"
    );
    assert!(
        s2c_srcs_seen.len() >= 2,
        "the s2c source address must change across server migration (saw {} distinct sources)",
        s2c_srcs_seen.len()
    );
    drop(s2c_srcs_seen);
    let s2c_cids_seen = s2c_cids.lock().unwrap().len();
    assert!(
        s2c_cids_seen >= 2,
        "the on-wire s2c CID must rotate across server migration (saw {s2c_cids_seen} distinct OneRtt CIDs)"
    );
    // EPS-02 closure: the client reflects the server's migration — it bumps its path_id and
    // rotates its c2s CID — so the c2s ConnId ALSO rotates across the move. With both
    // directions rotating, a both-networks observer cannot relink the session by either CID.
    let c2s_cids_seen = c2s_cids.lock().unwrap().len();
    assert!(
        c2s_cids_seen >= 2,
        "the client's c2s CID must rotate across a server migration (EPS-02 closure; saw {c2s_cids_seen})"
    );

    server.await.unwrap();
}

/// ε / WIRE v5 (P4b) — the inbound CID demux window SLIDES as the client migrates,
/// so a session keeps routing across MANY more than K=4 migrations (the
/// pre-registered window covers only the first K). The client migrates HOPS >> K
/// times, sending a distinct message after each; the server receives EVERY one,
/// which is only possible if it slid its inbound CID window (post-AEAD, on each
/// new authenticated path_id) to cover the rotated CID. A stuck window would
/// strand the out-of-window message and this would time out.
///
/// This isolates the CID *routing* (the slide) from the migration peer-follow
/// (promote, which governs the reverse/ACK direction): no echo is required, and
/// the reliable retransmit makes the data delivery race-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_window_slides_across_many_migrations() {
    use std::collections::HashSet;
    const HOPS: usize = 12; // >> K = 4 — only a sliding window keeps routing this far

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    // Collect HOPS+1 DISTINCT messages. Each arrives only if its rotated CID routed
    // — i.e. the window slid. Retransmits (no ACK reaches the client until the peer
    // follows) are deduplicated by the reliable stream, so this counts distinct.
    let server = tokio::spawn(async move {
        let s = listener.accept().await.expect("accept").session();
        let mut got: HashSet<Vec<u8>> = HashSet::new();
        while got.len() <= HOPS {
            let m = s
                .recv()
                .await
                .expect("server recv (the inbound window must slide)");
            got.insert(m.to_vec());
        }
        got.len()
    });

    let transport = UdpClientTransport::connect(addr)
        .await
        .expect("udp connect");
    let client = PhantomSession::connect_with_transport(&addr.to_string(), transport, key);

    client.send(b"msg-0".to_vec()).await.expect("send 0");
    for i in 1..=HOPS {
        client
            .migrate("127.0.0.1:0".to_string())
            .await
            .expect("migrate");
        client
            .send(format!("msg-{i}").into_bytes())
            .await
            .expect("send hop");
        // Let each hop's packet route + the slide apply before the next migration.
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    let count = timeout(Duration::from_secs(25), server)
        .await
        .expect("server must receive every hop's message — the inbound window slid")
        .unwrap();
    assert_eq!(
        count,
        HOPS + 1,
        "all rotated CIDs routed via the slid window"
    );
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

/// Direction #3 (idle keep-alive PINGs): a **download-only** path now detects a
/// silently-dead downstream. The client never sends application data after the
/// warm-up — it only ACKs (and, before the fix, has nothing in flight) — so the
/// pure inactivity sweep (gated on `inflight > 0`) would NEVER trip for it and a
/// dead path would go unnoticed forever. With idle keep-alives enabled, the idle
/// client emits an encrypted `KEEPALIVE` PING every interval; once the path is
/// cut, that PING goes unanswered (no PONG → the probe stays outstanding and
/// inbound stays silent), so the same liveness sweep declares the path down →
/// `Migrating` → `Dead`, exactly like an active path. `recv()` must error, never
/// hang.
///
/// The distinction from `udp_liveness_dead_path_surfaces_migrating_then_dead` is
/// load-bearing: that test calls `client.send()` after the cut to manufacture
/// in-flight data; THIS test deliberately sends nothing post-warm-up, so the
/// keep-alive PING is the *only* thing that can anchor the liveness timer. Without
/// Direction #3 it times out (the download-only client never leaves `Connected`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_keepalive_download_only_path_detects_dead_downstream() {
    use phantom_protocol::api::session::ConnectionState;
    use phantom_protocol::transport::liveness::LivenessConfig;
    use std::sync::atomic::Ordering;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    // The server sends ONE warm-up message (a tiny "download"), then goes quiet —
    // it never asks the client for anything, so the client is purely a downloader.
    // It also answers keep-alive PINGs automatically (the pump PONGs them), so
    // while the path is alive the client must NOT trip; only the cut kills it.
    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        session
            .send(b"download-chunk".to_vec())
            .await
            .expect("server send");
        // Stay alive (and keep PONGing keep-alives) until the test cuts the path
        // and the session tears down.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let (relay_addr, forward) = spawn_cuttable_relay(server_addr).await;
    let transport = UdpClientTransport::connect(relay_addr)
        .await
        .expect("connect");
    let client = PhantomSession::connect_with_transport(&relay_addr.to_string(), transport, key);

    // The client receives the one download chunk — and sends NOTHING in reply
    // (download-only). It must open the session with an initial client->server
    // packet first (the handshake), but after this point it only ACKs + keep-alives.
    let chunk = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("recv download chunk");
    assert_eq!(chunk, b"download-chunk");

    // Fast liveness thresholds (40 ms keep-alive, ~30 ms-to-down, 300 ms-to-dead).
    assert!(
        client.set_liveness_config(LivenessConfig::for_test()).await,
        "session must be established to set the liveness config"
    );

    // The path is fully idle from the client's side: it has nothing to send and is
    // not receiving. Let a few keep-alive intervals elapse WHILE the path is alive
    // and assert the client stays Connected — a keep-alive that is being PONGed
    // must NOT false-trip the liveness sweep (the PONG refreshes activity).
    for _ in 0..15 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            client.connection_state(),
            ConnectionState::Connected,
            "an idle path whose keep-alives are PONGed must stay Connected"
        );
    }

    // Now SEVER the downstream. The client keeps sending keep-alive PINGs, but no
    // PONG comes back and no inbound arrives → the outstanding probe + inbound
    // silence drive the liveness sweep to PathDown even though the client has zero
    // application data in flight (the download-only property). The client sends NO
    // app data here — the keep-alive is the only liveness anchor.
    forward.store(false, Ordering::Relaxed);

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
        "a dead DOWNLOAD-ONLY path must surface Migrating via the idle keep-alive probe"
    );
    assert!(
        saw_dead,
        "no recovery before the idle-timeout must surface Dead on a download-only path"
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
    // Keep-alives off — this test drives the inactivity sweep with explicit sends.
    let cfg = LivenessConfig {
        min_pto: Duration::from_millis(10),
        path_down_ptos: 3,
        idle_timeout: Duration::from_secs(20),
        keepalive_interval: None,
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

/// ★ M-3 mandatory bidirectional test: a live session **survives a PASSIVE NAT
/// rebind** mid-download — the client's apparent source address (as seen by the
/// server) changes WITHOUT the client calling `migrate()`, so its `path_id` stays
/// 0 (the always-Validated handshake path). Pre-fix the server's challenge logic
/// was path-id-gated, so it skipped the Validated path 0, never challenged the new
/// source, never promoted it, and kept sending the downstream (server->client)
/// echoes to the OLD, now-dead address → the reliable stream stalled. The fix
/// makes detection ADDRESS-driven: an AEAD-authenticated frame from a new source
/// on a Validated path is challenged on the reserved validation path-id, validated
/// from the claimed address (anti-spoof preserved), promoted, and the server's
/// downstream follows — all with NO re-handshake and NO client `migrate()`.
///
/// A relay forwards `client <-> relay <-> server`. The relay forwards c2s through
/// one of two upstream sockets (each `connect`ed to the server from a distinct
/// local port = a distinct apparent client source) and receives s2c on the same
/// one. Flipping `use_b` mid-stream rewrites the client's apparent source from
/// `upstream_a`'s port to `upstream_b`'s — exactly a passive rebind. The client
/// socket is untouched; it never migrates. The post-rebind echoes can only arrive
/// if the server detected the new source and switched its downstream to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_passive_rebind_recovers_without_client_migrate() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    const ROUNDS: usize = 8;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    // The server echoes ROUNDS messages over the SAME accepted session. It must
    // keep serving that one session across the passive rebind and follow the peer
    // to the new (relay upstream) source — never re-accepting / re-handshaking.
    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        for _ in 0..ROUNDS {
            let m = session.recv().await.expect("server recv");
            session.send(m).await.expect("server echo");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    // Relay: client <-> relay <-> server, with TWO upstream sockets toward the
    // server (distinct local ports = distinct apparent client sources). `use_b`
    // selects the active upstream for BOTH directions, so flipping it rewrites the
    // client's apparent source to the server (a passive rebind) while keeping the
    // client's own socket untouched.
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let up_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    up_a.connect(server_addr).await.unwrap();
    let up_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    up_b.connect(server_addr).await.unwrap();
    let use_b = Arc::new(AtomicBool::new(false));
    let ub = use_b.clone();
    tokio::spawn(async move {
        let mut c2s = vec![0u8; 2048];
        let mut sa = vec![0u8; 2048];
        let mut sb = vec![0u8; 2048];
        let mut client_addr: Option<std::net::SocketAddr> = None;
        loop {
            tokio::select! {
                r = relay.recv_from(&mut c2s) => {
                    let (n, from) = match r { Ok(x) => x, Err(_) => continue };
                    client_addr = Some(from);
                    // Forward c2s out the currently-selected upstream — this is what
                    // changes the apparent client source the server sees on a flip.
                    if ub.load(Ordering::Relaxed) {
                        let _ = up_b.send(&c2s[..n]).await;
                    } else {
                        let _ = up_a.send(&c2s[..n]).await;
                    }
                }
                r = up_a.recv(&mut sa) => {
                    let n = match r { Ok(x) => x, Err(_) => continue };
                    // Once the rebind flips to B, the OLD upstream (A) is dead: drop
                    // its s2c. This SEVERS the server's stale downstream and forces the
                    // M-3 recovery — if the server keeps echoing to A, the client never
                    // sees those packets and the stream stalls. (Pre-fix this is exactly
                    // what happens, so the test times out → it guards the bug.)
                    if !ub.load(Ordering::Relaxed) {
                        if let Some(ca) = client_addr { let _ = relay.send_to(&sa[..n], ca).await; }
                    }
                }
                r = up_b.recv(&mut sb) => {
                    let n = match r { Ok(x) => x, Err(_) => continue };
                    if ub.load(Ordering::Relaxed) {
                        if let Some(ca) = client_addr { let _ = relay.send_to(&sb[..n], ca).await; }
                    }
                }
            }
        }
    });

    let transport = UdpClientTransport::connect(relay_addr).await.unwrap();
    let client = PhantomSession::connect_with_transport(&relay_addr.to_string(), transport, key);

    // Round 0 establishes the data plane via upstream A (the server's view of the
    // client source = up_a's port).
    let m0 = b"round-0-pre-rebind".to_vec();
    client.send(m0.clone()).await.expect("send 0");
    let e0 = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("recv 0");
    assert_eq!(e0, m0, "pre-rebind echo must be byte-exact");

    // PASSIVE REBIND: flip the relay to upstream B. The server now sees the client
    // arriving from a NEW source, but the client never called migrate() — its
    // path_id is still 0. The server must detect this address change, challenge the
    // new source on the reserved validation path-id, validate it, and switch its
    // downstream so the echoes keep flowing.
    use_b.store(true, Ordering::Relaxed);

    // Rounds 1..ROUNDS: the reliable byte stream continues byte-exact across the
    // passive rebind with NO re-handshake and NO client migrate(). This only works
    // if M-3's address-driven challenge promoted the new source on the server.
    for i in 1..ROUNDS {
        let m = format!("round-{i}-post-rebind-{}", "y".repeat(i * 5)).into_bytes();
        client.send(m.clone()).await.expect("send post-rebind");
        let e = timeout(Duration::from_secs(10), client.recv())
            .await
            .expect("no timeout (the session must survive the passive rebind)")
            .expect("recv post-rebind");
        assert_eq!(e, m, "post-rebind echo must be byte-exact (round {i})");
    }

    server.await.unwrap();
}

/// T5.5(b) — a live, lossy, multi-rekey session must keep delivering through the
/// receive-side catch-up GATE. With a low rekey high-watermark on BOTH ends, the
/// session rekeys repeatedly mid-exchange; once the data plane is warm the relay
/// drops every 3rd datagram in each direction, forcing reliable retransmits AT
/// THE NEW EPOCH. Those retransmits only pass the gate (which rejects a forward
/// epoch lacking the `REKEY` flag) because the sender RE-ADVERTISES `REKEY` on
/// every new-epoch packet while the rekey is unconfirmed — the single trigger
/// packet alone would be lost. If the sender did not re-advertise (or the gate
/// rejected the unflagged retransmits), the reliable stream would stall and this
/// would time out. We assert every echo is byte-exact and that a rekey fired.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_rekey_under_loss_survives_the_catchup_gate() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    const MSGS: usize = 24;
    const THRESH: u64 = 8;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    // Server: lower the rekey watermark on the established session, then echo
    // exactly MSGS messages lock-step.
    let server = tokio::spawn(async move {
        let s = listener.accept().await.expect("accept").session();
        assert!(
            s.set_rekey_threshold(THRESH).await,
            "server session established"
        );
        for _ in 0..MSGS {
            let m = s.recv().await.expect("server recv");
            s.send(m).await.expect("server echo");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    // Lossy relay: client <-> relay <-> server. While `lossy` is set, drop every
    // 3rd datagram in EACH direction (independent counters), forcing ARQ.
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upstream.connect(server_addr).await.unwrap();
    let lossy = Arc::new(AtomicBool::new(false));
    let lossy_relay = lossy.clone();
    tokio::spawn(async move {
        let mut c2s = vec![0u8; 4096];
        let mut s2c = vec![0u8; 4096];
        let mut client_addr: Option<std::net::SocketAddr> = None;
        let c2s_n = AtomicU64::new(0);
        let s2c_n = AtomicU64::new(0);
        loop {
            tokio::select! {
                r = relay.recv_from(&mut c2s) => {
                    let (n, from) = match r { Ok(x) => x, Err(_) => continue };
                    client_addr = Some(from);
                    let i = c2s_n.fetch_add(1, Ordering::Relaxed);
                    if lossy_relay.load(Ordering::Relaxed) && i % 3 == 2 { continue; }
                    let _ = upstream.send(&c2s[..n]).await;
                }
                r = upstream.recv(&mut s2c) => {
                    let n = match r { Ok(x) => x, Err(_) => continue };
                    let i = s2c_n.fetch_add(1, Ordering::Relaxed);
                    if lossy_relay.load(Ordering::Relaxed) && i % 3 == 2 { continue; }
                    if let Some(ca) = client_addr { let _ = relay.send_to(&s2c[..n], ca).await; }
                }
            }
        }
    });

    let transport = UdpClientTransport::connect(relay_addr).await.unwrap();
    let client = PhantomSession::connect_with_transport(&relay_addr.to_string(), transport, key);

    // Warm up cleanly (handshake + first echo) before enabling loss, so the
    // handshake is not flaky and the loss lands on the data plane.
    client.send(b"warmup".to_vec()).await.unwrap();
    let echo = timeout(Duration::from_secs(10), client.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, b"warmup");
    // Session is established now → lower the client watermark too.
    assert!(
        client.set_rekey_threshold(THRESH).await,
        "client session established"
    );

    // Make the network lossy and push the rest through repeated mid-session rekeys.
    lossy.store(true, Ordering::Relaxed);
    for i in 1..MSGS {
        let msg = format!("lossy-rekey-msg-{i:04}").into_bytes();
        client.send(msg.clone()).await.unwrap();
        let echo = timeout(Duration::from_secs(30), client.recv())
            .await
            .expect("no timeout — the gate must not strand retransmits at the new epoch")
            .expect("client recv");
        assert_eq!(echo, msg, "byte-exact echo #{i} under loss + rekey");
    }

    let epoch = client.current_epoch().await.expect("established");
    assert!(
        epoch > 0,
        "the low watermark must have driven at least one mid-session rekey (epoch={epoch})"
    );

    server.await.unwrap();
}

/// WIRE v6 (c) — a live session with PADÉ size padding enabled on BOTH ends still
/// delivers byte-exact, across a range of payload lengths (so the receiver strips
/// every pad amount correctly through the real pump: apply-on-send, strip-on-recv,
/// for small, bucket-edge, and large payloads). The exact PADÉ bucketing of a
/// packet is pinned separately by the `security_invariants` unit test; this proves
/// the end-to-end data plane is not broken by padding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_size_padding_delivers_byte_exact() {
    use phantom_protocol::api::session::TrafficShapingConfig;
    use phantom_protocol::transport::shaping::PaddingPolicy;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    let server = tokio::spawn(async move {
        let s = listener.accept().await.expect("accept").session();
        assert!(
            s.set_traffic_shaping(TrafficShapingConfig {
                padding: PaddingPolicy::Padme,
                jitter_ms: 0,
                cover_interval_ms: 0,
            })
            .await,
            "server session established"
        );
        // 1 warmup + 6 loop messages = 7 echoes.
        for _ in 0..7 {
            let m = s.recv().await.expect("server recv");
            s.send(m).await.expect("server echo");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    let transport = UdpClientTransport::connect(addr).await.unwrap();
    let client = PhantomSession::connect_with_transport(&addr.to_string(), transport, key);

    // Warm up + enable padding on the client (post-establish).
    client.send(b"warmup".to_vec()).await.unwrap();
    let echo = timeout(Duration::from_secs(10), client.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, b"warmup");
    assert!(
        client
            .set_traffic_shaping(TrafficShapingConfig {
                padding: PaddingPolicy::Padme,
                jitter_ms: 0,
                cover_interval_ms: 0,
            })
            .await,
        "client session established"
    );

    // A range of payload lengths — tiny, bucket-edge, and large — all echo
    // byte-exact, so the receiver strips every pad amount correctly.
    for len in [1usize, 2, 30, 63, 200, 700] {
        let msg = vec![0xA5u8; len];
        client.send(msg.clone()).await.unwrap();
        let echo = timeout(Duration::from_secs(15), client.recv())
            .await
            .expect("no timeout")
            .expect("client recv");
        assert_eq!(echo, msg, "byte-exact echo of a {len}-byte padded message");
    }

    server.await.unwrap();
}

/// WIRE v6 (d) — a live session with send-timing jitter enabled still delivers
/// byte-exact (jitter only delays sends; it must not reorder, drop, or corrupt the
/// stream). The jitter bound itself is unit-tested in `transport::shaping`; this
/// proves the data plane survives the added per-packet delay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_timing_jitter_delivers_byte_exact() {
    use phantom_protocol::api::session::TrafficShapingConfig;
    use phantom_protocol::transport::shaping::PaddingPolicy;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    let server = tokio::spawn(async move {
        let s = listener.accept().await.expect("accept").session();
        // Jitter on the server side too (and padding, to exercise both together).
        assert!(
            s.set_traffic_shaping(TrafficShapingConfig {
                padding: PaddingPolicy::Padme,
                jitter_ms: 15,
                cover_interval_ms: 0,
            })
            .await
        );
        for _ in 0..5 {
            let m = s.recv().await.expect("server recv");
            s.send(m).await.expect("server echo");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let transport = UdpClientTransport::connect(addr).await.unwrap();
    let client = PhantomSession::connect_with_transport(&addr.to_string(), transport, key);
    client.send(b"warmup".to_vec()).await.unwrap();
    let echo = timeout(Duration::from_secs(10), client.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, b"warmup");
    assert!(
        client
            .set_traffic_shaping(TrafficShapingConfig {
                padding: PaddingPolicy::None,
                jitter_ms: 15,
                cover_interval_ms: 0,
            })
            .await
    );

    for i in 0..4 {
        let msg = format!("jitter-msg-{i}").into_bytes();
        client.send(msg.clone()).await.unwrap();
        let echo = timeout(Duration::from_secs(15), client.recv())
            .await
            .expect("no timeout — jitter only delays, never drops")
            .expect("client recv");
        assert_eq!(echo, msg, "byte-exact echo #{i} with timing jitter on");
    }

    server.await.unwrap();
}

/// WIRE v6 (e) — cover traffic: with a cover floor interval set, an otherwise-idle
/// session emits encrypted COVER dummy packets (so silence no longer leaks), and
/// those packets are DROPPED by the peer — they never surface in `recv()`. A real
/// message after the idle window still delivers byte-exact (cover doesn't break the
/// data plane).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_cover_traffic_fills_idle_and_is_dropped() {
    use phantom_protocol::api::session::TrafficShapingConfig;
    use phantom_protocol::transport::shaping::PaddingPolicy;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    let server = tokio::spawn(async move {
        let s = listener.accept().await.expect("accept").session();
        // Server enables cover too; it must never deliver a client cover packet as
        // application data (recv only ever returns the real message below).
        assert!(
            s.set_traffic_shaping(TrafficShapingConfig {
                padding: PaddingPolicy::None,
                jitter_ms: 0,
                cover_interval_ms: 40,
            })
            .await
        );
        // The server's recv must only ever return the two REAL messages — never a
        // (dropped) cover packet, even though cover is flowing both ways.
        for expected in [b"warmup".to_vec(), b"after-idle".to_vec()] {
            let m = s.recv().await.expect("server recv");
            assert_eq!(
                m, expected,
                "server must only recv real messages, never cover"
            );
            s.send(m).await.expect("server echo");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // Recording relay: count client->server datagrams while `recording` is set.
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upstream.connect(server_addr).await.unwrap();
    let recording = Arc::new(AtomicBool::new(false));
    let c2s_count = Arc::new(AtomicUsize::new(0));
    let rec = recording.clone();
    let cnt = c2s_count.clone();
    tokio::spawn(async move {
        let mut c2s = vec![0u8; 4096];
        let mut s2c = vec![0u8; 4096];
        let mut client_addr: Option<std::net::SocketAddr> = None;
        loop {
            tokio::select! {
                r = relay.recv_from(&mut c2s) => {
                    let (n, from) = match r { Ok(x) => x, Err(_) => continue };
                    client_addr = Some(from);
                    if rec.load(Ordering::Relaxed) { cnt.fetch_add(1, Ordering::Relaxed); }
                    let _ = upstream.send(&c2s[..n]).await;
                }
                r = upstream.recv(&mut s2c) => {
                    let n = match r { Ok(x) => x, Err(_) => continue };
                    if let Some(ca) = client_addr { let _ = relay.send_to(&s2c[..n], ca).await; }
                }
            }
        }
    });

    let transport = UdpClientTransport::connect(relay_addr).await.unwrap();
    let client = PhantomSession::connect_with_transport(&relay_addr.to_string(), transport, key);

    // Warm up, then enable cover with a 40 ms floor (25 packets/sec).
    client.send(b"warmup".to_vec()).await.unwrap();
    let echo = timeout(Duration::from_secs(10), client.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, b"warmup");
    assert!(
        client
            .set_traffic_shaping(TrafficShapingConfig {
                padding: PaddingPolicy::None,
                jitter_ms: 0,
                cover_interval_ms: 40,
            })
            .await
    );

    // Go idle (send nothing) for ~300 ms while recording. The client must emit cover
    // packets to maintain the floor rate → the relay sees client->server datagrams.
    recording.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(300)).await;
    recording.store(false, Ordering::Relaxed);
    let covered = c2s_count.load(Ordering::Relaxed);
    assert!(
        covered > 0,
        "cover traffic must fill the idle window with client->server packets (got {covered})"
    );

    // The data plane still works: a real message echoes byte-exact, and `recv()`
    // returns exactly it — never a (dropped) cover packet.
    client.send(b"after-idle".to_vec()).await.unwrap();
    let echo = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("client recv");
    assert_eq!(
        echo, b"after-idle",
        "recv must return the real message, never cover"
    );

    server.await.unwrap();
}

/// FFI shim smoke test — `connect_pinned_udp` is the UniFFI-exported free function
/// that opens a UDP client session with key pinning, mirroring `connect_pinned` for TCP.
/// Verifies the full handshake + encrypted data exchange over the production
/// `UdpClientTransport` path, reachable by mobile / FFI callers with only
/// `(host, port, pinned_key)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_ffi_connect_pinned_udp_roundtrip() {
    use phantom_protocol::api::session::connect_pinned_udp;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let local: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key_bytes = listener.verifying_key_bytes();

    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        let msg = session.recv().await.expect("server recv");
        assert_eq!(msg, b"ffi-udp-hello");
        session
            .send(b"ffi-udp-reply".to_vec())
            .await
            .expect("server send");
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let client = connect_pinned_udp("127.0.0.1".to_string(), local.port(), key_bytes)
        .await
        .expect("connect_pinned_udp");
    client
        .send(b"ffi-udp-hello".to_vec())
        .await
        .expect("client send");
    let reply = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("client recv");
    assert_eq!(reply, b"ffi-udp-reply");
    server.await.unwrap();
}

/// #9 — traffic-shaping config can be set BEFORE the (async) client handshake
/// completes, and is applied when the session installs — so the very first data
/// packets are already shaped (no "warm up then configure" gap). `set_traffic_shaping`
/// is accepted while still connecting (stored as pending), and `traffic_shaping()`
/// reads it back once established.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_shaping_set_before_establishment_applies() {
    use phantom_protocol::api::session::TrafficShapingConfig;
    use phantom_protocol::transport::shaping::PaddingPolicy;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    let server = tokio::spawn(async move {
        let s = listener.accept().await.expect("accept").session();
        let m = s.recv().await.expect("server recv");
        s.send(m).await.expect("server echo");
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let transport = UdpClientTransport::connect(addr).await.unwrap();
    let client = PhantomSession::connect_with_transport(&addr.to_string(), transport, key);

    // IMMEDIATELY — before the background handshake completes — set shaping. It must
    // be accepted (stored pending), and not yet readable (session not installed).
    let cfg = TrafficShapingConfig {
        padding: PaddingPolicy::Padme,
        jitter_ms: 7,
        cover_interval_ms: 250,
    };
    assert!(
        client.set_traffic_shaping(cfg).await,
        "shaping must be accepted while still connecting (stored pending)"
    );

    // Drive establishment.
    client.send(b"hello".to_vec()).await.unwrap();
    let echo = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("client recv");
    assert_eq!(echo, b"hello");

    // The pending config was applied at session install — readable now.
    assert_eq!(
        client.traffic_shaping().await,
        Some(cfg),
        "pre-establishment shaping config must be applied to the installed session"
    );

    server.await.unwrap();
}

/// Smoke-tests `connect_pinned_udp_with_resumption` over a live UDP loopback: an
/// unknown (synthetic) hint forces the server to reject 0-RTT and fall back to a
/// normal 1-RTT handshake (security invariant 9), and the byte-exact round-trip
/// still succeeds. Empty early_data avoids the rejected-early-data re-queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_ffi_connect_pinned_udp_resumption_1rtt_fallback() {
    use phantom_protocol::api::session::connect_pinned_udp_with_resumption;
    use phantom_protocol::api::session::ResumptionHint;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let local: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key_bytes = listener.verifying_key_bytes();

    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        let msg = session.recv().await.expect("server recv");
        assert_eq!(msg, b"ffi-udp-resume-hello");
        session
            .send(b"ffi-udp-resume-reply".to_vec())
            .await
            .expect("server send");
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // A synthetic (unknown) hint: the server has no matching ticket, so the
    // handshake falls back to 1-RTT (security invariant 9). We pass empty
    // early_data so nothing is re-queued on rejection (C3 retransmit contract).
    // The test exercises the connect path over UDP, not 0-RTT acceptance.
    let hint = ResumptionHint::new(vec![7u8; 32], vec![9u8; 32]);
    let client = connect_pinned_udp_with_resumption(
        "127.0.0.1".to_string(),
        local.port(),
        key_bytes,
        hint,
        vec![],
    )
    .await
    .expect("connect_pinned_udp_with_resumption");
    client
        .send(b"ffi-udp-resume-hello".to_vec())
        .await
        .expect("client send");
    let reply = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("client recv");
    assert_eq!(reply, b"ffi-udp-resume-reply");
    server.await.unwrap();
}

/// `is_shutting_down` reflects `shutdown()`, and `accept()` after shutdown returns
/// `ConnectionClosed` — exercises the newly UniFFI-exported listener surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_listener_shutdown_flag_is_observable() {
    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    assert!(!listener.is_shutting_down());
    listener.shutdown();
    assert!(listener.is_shutting_down());
    let result = listener.accept().await;
    assert!(matches!(result, Err(phantom_protocol::CoreError::ConnectionClosed)));
}

/// Headline regression: a session built through the FFI shim `connect_pinned_udp`
/// performs a REAL single-path connection migration mid-exchange. Over the TCP
/// `connect_pinned` shim `migrate()` is a no-op; this proves the UDP FFI path wires
/// `migrate()` through to a genuine socket rebind, with the reliable byte stream
/// surviving byte-exact and no re-handshake. Faithful FFI-path analogue of
/// `udp_integration_migration_survives_mid_exchange`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_ffi_migrate_survives_mid_exchange() {
    use phantom_protocol::api::session::connect_pinned_udp;
    const ROUNDS: usize = 8;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let local: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key_bytes = listener.verifying_key_bytes();

    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        for _ in 0..ROUNDS {
            let m = session.recv().await.expect("server recv");
            session.send(m).await.expect("server echo");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let client = connect_pinned_udp("127.0.0.1".to_string(), local.port(), key_bytes)
        .await
        .expect("connect_pinned_udp");

    let m0 = b"round-0-pre-migration".to_vec();
    client.send(m0.clone()).await.expect("send 0");
    let e0 = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("recv 0");
    assert_eq!(e0, m0, "pre-migration echo must be byte-exact");

    // The FFI-exported migrate() must perform a real rebind (not the TCP no-op).
    client
        .migrate("127.0.0.1:0".to_string())
        .await
        .expect("migrate");

    for i in 1..ROUNDS {
        let m = format!("round-{i}-post-migration-{}", "x".repeat(i * 7)).into_bytes();
        client.send(m.clone()).await.expect("send post-migration");
        let e = timeout(Duration::from_secs(10), client.recv())
            .await
            .expect("no timeout (the FFI session must survive the migration)")
            .expect("recv post-migration");
        assert_eq!(e, m, "post-migration echo must be byte-exact (round {i})");
    }

    server.await.unwrap();
}

/// Stronger headline regression: proves the FFI `connect_pinned_udp` `migrate()`
/// performs a REAL local-socket rebind, not the silent no-op it would be over TCP
/// (or if the migration control surface were swallowed before reaching
/// `UdpClientTransport::migrate`). A relay between client and server records every
/// distinct client source address; a real rebind makes the relay observe a NEW
/// source after `migrate()` (a no-op would keep exactly one). The reliable byte
/// stream also survives the migration byte-exact through the relay. The server-side
/// migration-follow is covered separately by
/// `udp_integration_migration_survives_mid_exchange`; here the relay masks the move
/// from the server so the assertion isolates the CLIENT rebind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_ffi_migrate_actually_rebinds_through_relay() {
    use phantom_protocol::api::session::connect_pinned_udp;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use tokio::net::UdpSocket;
    const ROUNDS: usize = 6;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key_bytes = listener.verifying_key_bytes();

    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        for _ in 0..ROUNDS {
            let m = session.recv().await.expect("server recv");
            session.send(m).await.expect("server echo");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    // Relay (client <-> relay <-> server) recording every DISTINCT client source
    // address. A real migrate() rebinds the client's local socket -> a new source
    // port -> a second distinct address here; a no-op migrate would keep one.
    //
    // Design: two UNCONNECTED sockets on the relay side. The inbound (facing client)
    // socket `relay` records client source addresses and forwards c2s to server_addr.
    // The outbound (facing server) socket `upstream` sends c2s using send_to and
    // receives s2c using recv_from; all s2c arrives from server_addr and is routed
    // back to the last-known client_addr. Unconnected sockets are used on both sides
    // to ensure recv_from sees the actual source (no connected-socket filtering).
    let client_srcs: Arc<Mutex<HashSet<std::net::SocketAddr>>> =
        Arc::new(Mutex::new(HashSet::new()));
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srcs = client_srcs.clone();
    tokio::spawn(async move {
        let mut c2s = vec![0u8; 2048];
        let mut s2c = vec![0u8; 2048];
        let mut client_addr: Option<std::net::SocketAddr> = None;
        let mut c2s_count = 0u32;
        let mut s2c_count = 0u32;
        loop {
            tokio::select! {
                r = relay.recv_from(&mut c2s) => {
                    let (n, from) = match r { Ok(x) => x, Err(_) => continue };
                    c2s_count += 1;
                    eprintln!("[relay] c2s #{c2s_count}: from={from}, n={n}, client_addr={client_addr:?}");
                    client_addr = Some(from);
                    srcs.lock().unwrap().insert(from);
                    let _ = upstream.send_to(&c2s[..n], server_addr).await;
                }
                r = upstream.recv_from(&mut s2c) => {
                    let (n, src) = match r { Ok(x) => x, Err(_) => continue };
                    s2c_count += 1;
                    eprintln!("[relay] s2c #{s2c_count}: from={src}, n={n}, to={client_addr:?}");
                    if let Some(ca) = client_addr {
                        let _ = relay.send_to(&s2c[..n], ca).await;
                    }
                }
            }
        }
    });

    // Build the client THROUGH the FFI shim, pointed at the relay.
    let client = connect_pinned_udp("127.0.0.1".to_string(), relay_addr.port(), key_bytes)
        .await
        .expect("connect_pinned_udp");

    let m0 = b"round-0-pre-migration".to_vec();
    client.send(m0.clone()).await.expect("send 0");
    let e0 = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("recv 0");
    assert_eq!(e0, m0, "pre-migration echo must be byte-exact");
    let before = client_srcs.lock().unwrap().len();
    assert!(before >= 1, "the client's original source must be seen pre-migration");

    // The FFI-exported migrate() must perform a real local-socket rebind.
    client.migrate("127.0.0.1:0".to_string()).await.expect("migrate");

    // Give the new socket a moment to bind and the path validation to complete
    // before the post-migration sends, so the relay sees the new source address.
    tokio::time::sleep(Duration::from_millis(50)).await;

    for i in 1..ROUNDS {
        let m = format!("round-{i}-post-migration-{}", "x".repeat(i * 7)).into_bytes();
        eprintln!("[test] round {i}: sending {} bytes", m.len());
        client.send(m.clone()).await.expect("send post-migration");
        eprintln!("[test] round {i}: waiting for recv");
        let e = timeout(Duration::from_secs(10), client.recv())
            .await
            .expect("no timeout (the FFI session must survive the migration)")
            .expect("recv post-migration");
        eprintln!("[test] round {i}: received {} bytes", e.len());
        assert_eq!(e, m, "post-migration echo must be byte-exact (round {i})");
    }

    // The relay observed a NEW client source address after migrate(): proof the FFI
    // migrate() actually rebound the local socket (a no-op would keep exactly one).
    let after = client_srcs.lock().unwrap().len();
    assert!(
        after >= 2 && after > before,
        "FFI migrate() must rebind the client socket to a new source address \
         (distinct client sources before {before}, after {after}); a no-op migrate \
         would keep exactly one"
    );

    server.await.unwrap();
}
