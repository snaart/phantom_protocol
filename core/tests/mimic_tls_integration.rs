//! Live end-to-end integration of the TLS-over-TCP active-mimicry transport
//! (queue item #13) over a real TCP loopback: a `PhantomListener::bind_mimic`
//! server and a `connect_pinned_mimic` client complete the full synthetic TLS
//! prelude AND the inner Phantom post-quantum handshake, then exchange encrypted
//! application data bidirectionally.
//!
//! `#[ignore]`-gated like the other loopback suites (`tcp_integration`,
//! `kcp_integration`) so it does not run on the default `cargo test`; the
//! `mimicry`-feature CI job runs it with `-- --ignored`. Requires the `mimicry`
//! feature (and a native, non-wasm target).
#![cfg(all(not(target_arch = "wasm32"), feature = "mimicry"))]

use std::net::SocketAddr;
use std::time::Duration;

use phantom_protocol::api::listener::PhantomListener;
use phantom_protocol::api::session::connect_pinned_mimic;
use tokio::time::timeout;

/// Full session over the mimicry transport: pinned connect, bidirectional
/// encrypted data, and the negative assertion that the application plaintext never
/// appears on the (TLS-record-wrapped) wire is already covered by the inner
/// session's own tests — here we prove the prelude + inner handshake + data path
/// all compose over a real socket through `bind_mimic` / `connect_pinned_mimic`.
#[tokio::test]
#[ignore = "real TCP loopback; run via the mimicry CI job with --ignored"]
async fn mimic_full_session_round_trip() {
    let listener = PhantomListener::bind_mimic("127.0.0.1:0".to_string())
        .await
        .expect("bind_mimic");
    let addr: SocketAddr = listener.local_addr().parse().expect("parse local_addr");
    let pinned = listener.verifying_key_bytes();

    // Server: accept one mimicry connection, echo a reply.
    let server = tokio::spawn(async move {
        let outcome = timeout(Duration::from_secs(15), listener.accept())
            .await
            .expect("accept did not time out")
            .expect("accept");
        let session = outcome.session();
        let got = timeout(Duration::from_secs(15), session.recv())
            .await
            .expect("server recv did not time out")
            .expect("server recv");
        assert_eq!(&got[..], b"hello over mimic-tls");
        session
            .send(b"reply over mimic-tls".to_vec())
            .await
            .expect("server send");
        // Keep the session alive briefly so the reply flushes before drop.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // Client: connect over the mimicry transport with a cover SNI, exchange data.
    let client = timeout(
        Duration::from_secs(15),
        connect_pinned_mimic(
            addr.ip().to_string(),
            addr.port(),
            pinned,
            "www.example-cdn.com".to_string(),
        ),
    )
    .await
    .expect("connect did not time out")
    .expect("connect_pinned_mimic");

    client
        .send(b"hello over mimic-tls".to_vec())
        .await
        .expect("client send");
    let reply = timeout(Duration::from_secs(15), client.recv())
        .await
        .expect("client recv did not time out")
        .expect("client recv");
    assert_eq!(&reply[..], b"reply over mimic-tls");

    server.await.expect("server task");
}
