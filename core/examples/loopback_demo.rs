//! End-to-end loopback demo (Phase 7.1).
//!
//! Spawns a [`PhantomListener`] and a [`PhantomSession`] in the same process,
//! exchanges encrypted messages, and prints what happened on the wire.
//!
//! Run:
//!
//! ```text
//! cargo run --manifest-path core/Cargo.toml --example loopback_demo
//! ```
//!
//! What it demonstrates end-to-end:
//! - Server creates a hybrid (Ed25519 + Dilithium3) signing keypair on bind.
//! - Server's `HybridVerifyingKey` is exported via `verifying_key_bytes()`
//!   and pinned by the client. This is the **Vuln-1 fix** from the May 2026
//!   security review — without pinning, any MITM with their own keypair
//!   could complete a handshake against a naive client.
//! - The handshake is hybrid PQ-secure (X25519 + Kyber768 KEM, Ed25519 +
//!   Dilithium3 signatures over the transcript).
//! - Application bytes after the handshake are AES-256-GCM-encrypted with
//!   per-direction keys derived from the shared secret; the wire bytes do
//!   not contain the plaintext.

use phantom_core::api::{PhantomListener, PhantomSession, TcpSessionTransport};
use phantom_core::crypto::hybrid_sign::HybridVerifyingKey;
use std::time::Duration;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Plumbing logger so we see the library's own `log::info!` lines.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // ── 1. Bind server ────────────────────────────────────────────────────
    // Port 0 → OS picks an ephemeral port.
    let listener = PhantomListener::bind("127.0.0.1:0".to_string()).await?;
    let server_addr: std::net::SocketAddr = listener.local_addr().parse()?;
    let server_key_bytes = listener.verifying_key_bytes();
    let expected_server_key = HybridVerifyingKey::from_bytes(&server_key_bytes)?;
    println!("▶ server listening on {}", server_addr);
    println!(
        "▶ server verifying_key ({} bytes) shared with client out-of-band",
        server_key_bytes.len(),
    );

    // ── 2. Server task ────────────────────────────────────────────────────
    let server_handle = tokio::spawn(async move {
        // Accept exactly one connection, echo one message, then close.
        let session = listener.accept().await.expect("accept failed");
        println!("▶ server: accepted connection from {}", session.peer_addr());

        let request = session.recv().await.expect("server recv failed");
        println!(
            "▶ server: got decrypted request ({} bytes): {:?}",
            request.len(),
            String::from_utf8_lossy(&request),
        );

        let reply = b"hello, post-quantum world".to_vec();
        session.send(reply).await.expect("server send failed");

        // Let the data pump drain.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = session.close().await;
    });

    // ── 3. Client connects, pinning the server key ────────────────────────
    let stream = TcpStream::connect(server_addr).await?;
    let transport = TcpSessionTransport::new(stream);
    let client_session = PhantomSession::connect_with_transport(
        &server_addr.to_string(),
        transport,
        expected_server_key,
    );
    println!("▶ client: started handshake (pinned server key required)");

    // Give the handshake a moment.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let request = b"ping from a pinned client".to_vec();
    client_session.send(request).await?;
    println!("▶ client: sent encrypted request");

    let reply = client_session.recv().await?;
    println!(
        "▶ client: got decrypted reply ({} bytes): {:?}",
        reply.len(),
        String::from_utf8_lossy(&reply),
    );

    server_handle.await?;
    client_session.close().await?;
    println!("▶ demo complete");
    Ok(())
}

