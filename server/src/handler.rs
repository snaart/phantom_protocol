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
//! - **Privacy posture:** per-connection identifiers (the peer address and the
//!   32-byte `SessionId`) are personally-correlatable, so they are logged only
//!   at DEBUG (`RUST_LOG=phantom_server=debug`). Default INFO/WARN/ERROR output
//!   carries no raw PII — aggregate session counts come from the OTel
//!   `session.active` gauge, not per-connection log lines.

use phantom_core::api::session::PhantomSession;
use phantom_core::CoreError;
use std::sync::Arc;

pub async fn run_echo_handler(session: Arc<PhantomSession>) {
    let peer = session.peer_addr();
    let id = session.id();
    // DEBUG: peer address + session id are correlatable (PII), so keep them off
    // the default log stream.
    tracing::debug!(peer = %peer, session_id = %id, "session connected");

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
                        tracing::debug!(session_id = %id, "peer closed during send");
                    } else {
                        // Errors stay visible at WARN, but without the
                        // correlatable session id (that is at DEBUG above).
                        tracing::warn!(error = %e, "session send failed");
                    }
                    break;
                }
            }
            Err(e) if is_peer_close(&e) => {
                tracing::debug!(session_id = %id, "peer closed");
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "session recv failed");
                break;
            }
        }
    }

    // Best-effort close on the way out — the session may already be
    // closed if the peer initiated the teardown.
    let _ = session.disconnect().await;
    tracing::debug!(session_id = %id, "session closed");
}

/// `CoreError` does not distinguish "peer closed cleanly" from
/// "channel torn down" at the type level — both surface as either
/// `ConnectionClosed` or a `NetworkError` whose payload mentions a
/// closed socket. Treat both as a graceful exit.
fn is_peer_close(e: &CoreError) -> bool {
    matches!(e, CoreError::ConnectionClosed)
        || matches!(e, CoreError::NetworkError(s) if s.contains("closed"))
}
