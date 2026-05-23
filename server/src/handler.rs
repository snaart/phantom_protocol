//! Default application handler — a trivial echo.
//!
//! Embedders REPLACE this with real application logic. It exists so
//! the reference server is end-to-end usable for smoke tests, load
//! benchmarks, and a sanity check that the handshake completed and
//! the post-handshake encrypted channel works.
//!
//! Contract:
//!
//! - Receive a frame, send it back unchanged.
//! - Exit cleanly on `CoreError::ConnectionClosed` or any
//!   `NetworkError` that surfaces from a peer-closed socket.
//! - Log per-message events at DEBUG and connection-level events at
//!   INFO (so a production deployment can route INFO to stdout and
//!   keep DEBUG behind `RUST_LOG=phantom_server=debug`).

use phantom_core::api::session::PhantomSession;
use phantom_core::CoreError;
use std::sync::Arc;

pub async fn run_echo_handler(session: Arc<PhantomSession>) {
    let peer = session.peer_addr();
    let id = session.id();
    tracing::info!(peer = %peer, session_id = %id, "session connected");

    loop {
        match session.recv().await {
            Ok(bytes) => {
                tracing::debug!(
                    session_id = %id,
                    bytes = bytes.len(),
                    "echo frame received"
                );
                if let Err(e) = session.send(bytes).await {
                    if is_peer_close(&e) {
                        tracing::info!(session_id = %id, "peer closed during send");
                    } else {
                        tracing::error!(session_id = %id, error = %e, "send failed");
                    }
                    break;
                }
            }
            Err(e) if is_peer_close(&e) => {
                tracing::info!(session_id = %id, "peer closed");
                break;
            }
            Err(e) => {
                tracing::error!(session_id = %id, error = %e, "recv failed");
                break;
            }
        }
    }

    // Best-effort close on the way out — the session may already be
    // closed if the peer initiated the teardown.
    let _ = session.disconnect().await;
    tracing::info!(session_id = %id, "session closed");
}

/// `CoreError` does not distinguish "peer closed cleanly" from
/// "channel torn down" at the type level — both surface as either
/// `ConnectionClosed` or a `NetworkError` whose payload mentions a
/// closed socket. Treat both as a graceful exit.
fn is_peer_close(e: &CoreError) -> bool {
    matches!(e, CoreError::ConnectionClosed)
        || matches!(e, CoreError::NetworkError(s) if s.contains("closed"))
}
