//! Closing a stream from both ends, end to end (test-only).
//!
//! A stream has two halves and each end closes only its own:
//! [`PhantomStream::disconnect`] sends a reliable FIN that the peer reads as end-of-stream,
//! and the other direction stays open until the peer sends a FIN of its own. These tests
//! drive that over a real client/server pair — the production handshake, and the same data
//! pump on both ends — and pin what a stream looks like afterwards from either end:
//!
//! * the end that closed first keeps reading what the peer sends afterwards, then EOF;
//! * a stream closed from both ends leaves both sides' tables, and nothing the peer sends
//!   on it later is taken for the peer opening a new stream;
//! * nothing written after a stream's own close reaches the peer behind its EOF.
//!
//! The link has a real, if short, delay. Every defect pinned here depends on the order in
//! which a peer's acknowledgement and its next frame arrive, and a FIFO delay line fixes
//! that order where an in-memory pipe only happens to have one.
//!
//! The module is declared `#[cfg(test)]` in `api/mod.rs`, so it carries no inner
//! `#![cfg(test)]` of its own.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{timeout, Instant};

use crate::api::full_duplex_tests::{establish_counted, shutdown};
use crate::api::session::{PhantomSession, MAX_STREAMS};
use crate::api::stream::PhantomStream;
use crate::errors::CoreError;

/// One-way delay of the simulated path. Short, because nothing here is about rate; non-zero,
/// because the order of arrival is the point.
const ONE_WAY: Duration = Duration::from_millis(2);
/// Fast enough that the link is never what a test waits on.
const LINK_BYTES_PER_SEC: u64 = 64 * 1024 * 1024;
/// Budget for a step that takes a few round trips. Generous so a loaded runner cannot fail
/// it: the failures these tests exist for are waits that never end, not slow ones.
const STEP: Duration = Duration::from_secs(10);
/// How long a stream that must not appear is given to appear.
const QUIET: Duration = Duration::from_millis(300);

async fn establish() -> (Arc<PhantomSession>, Arc<PhantomSession>) {
    let (client, server, _) = establish_counted(ONE_WAY, LINK_BYTES_PER_SEC).await;
    (client, server)
}

/// The next `recv()` on `stream`, which has to return within [`STEP`].
async fn next_read(stream: &PhantomStream, who: &str) -> Result<Option<Vec<u8>>, CoreError> {
    timeout(STEP, stream.recv()).await.unwrap_or_else(|_| {
        panic!(
            "{who}: recv() on stream {} did not return",
            stream.stream_id()
        )
    })
}

/// The next stream `session` accepts, which has to arrive within [`STEP`].
async fn accept(session: &PhantomSession, who: &str) -> Arc<PhantomStream> {
    timeout(STEP, session.accept_stream())
        .await
        .unwrap_or_else(|_| panic!("{who}: no stream was accepted"))
        .expect("accept_stream")
}

/// Nothing surfaces on `session.accept_stream()` within [`QUIET`].
async fn assert_nothing_accepted(session: &PhantomSession, what: &str) {
    if let Ok(Ok(stream)) = timeout(QUIET, session.accept_stream()).await {
        panic!(
            "{what} surfaced on accept_stream as a new stream {}",
            stream.stream_id()
        );
    }
}

/// Wait until `session` has no user stream open and none routed: every stream it held has
/// been closed from both ends and dropped.
async fn wait_until_no_streams(session: &PhantomSession, who: &str) {
    let deadline = Instant::now() + STEP;
    loop {
        let open = session.observability().snapshot().active_streams;
        let routed = session.demux().active_stream_count();
        if open == 0 && routed == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{who}: {open} stream(s) still open and {routed} still routed — a stream closed \
             from both ends was never dropped"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The end that closes first still reads the peer's reply and then its EOF, and the reply
/// does not come back as a stream of its own.
///
/// A FIN closes one direction. Tearing the whole stream down when the peer acknowledged it
/// took the read half with it: the handle's channel closed, so its next `recv()` reported an
/// abnormal end, and the reply — arriving on an id the table no longer held — was taken for
/// the peer opening a new stream, one with this side's own parity that nothing would ever
/// close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_end_that_closes_first_still_reads_the_reply() {
    let (client, server) = establish().await;

    let ours = client.open_stream();
    ours.send_reliable(b"ping".to_vec())
        .await
        .expect("send ping");
    let theirs = accept(&server, "server").await;
    assert_eq!(theirs.stream_id(), ours.stream_id());
    assert_eq!(
        next_read(&theirs, "server").await.expect("read ping"),
        Some(b"ping".to_vec())
    );

    ours.disconnect().await.expect("close the client's half");
    assert_eq!(
        next_read(&theirs, "server")
            .await
            .expect("read the client's FIN"),
        None,
        "the server must read the client's close as end-of-stream"
    );

    // The server acknowledged the client's FIN before its application saw the EOF, so on
    // this FIFO link the client knows its FIN arrived before anything below reaches it.
    theirs
        .send_reliable(b"pong".to_vec())
        .await
        .expect("send the reply");
    theirs.disconnect().await.expect("close the server's half");

    assert_eq!(
        next_read(&ours, "client")
            .await
            .expect("closing its own half must not end the client's read half"),
        Some(b"pong".to_vec())
    );
    assert_eq!(
        next_read(&ours, "client")
            .await
            .expect("read the server's FIN"),
        None
    );
    assert_nothing_accepted(&client, "the reply on a stream the client opened").await;

    wait_until_no_streams(&client, "client").await;
    wait_until_no_streams(&server, "server").await;
    shutdown(&client, &server).await;
}

/// Data the peer sends after the first close reaches the original handle rather than a
/// stream that was never opened.
///
/// This is the variant of the test above in which the peer had already written on the
/// stream. Its later segments then carry offsets above zero, so a stream made up afresh for
/// them would hold them in its reorder buffer for ever — while acknowledging them, so the
/// peer would retire data no application had read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_the_peer_sends_after_the_first_close_is_not_stranded() {
    let (client, server) = establish().await;

    let ours = client.open_stream();
    ours.send_reliable(b"ping".to_vec())
        .await
        .expect("send ping");
    let theirs = accept(&server, "server").await;
    assert_eq!(
        next_read(&theirs, "server").await.expect("read ping"),
        Some(b"ping".to_vec())
    );
    theirs
        .send_reliable(b"one".to_vec())
        .await
        .expect("send before the close");
    assert_eq!(
        next_read(&ours, "client").await.expect("read one"),
        Some(b"one".to_vec())
    );

    ours.disconnect().await.expect("close the client's half");
    assert_eq!(
        next_read(&theirs, "server")
            .await
            .expect("read the client's FIN"),
        None
    );

    theirs
        .send_reliable(b"two".to_vec())
        .await
        .expect("send after the close");
    theirs
        .send_reliable(b"three".to_vec())
        .await
        .expect("send after the close");
    theirs.disconnect().await.expect("close the server's half");

    for expected in [&b"two"[..], &b"three"[..]] {
        assert_eq!(
            next_read(&ours, "client")
                .await
                .expect("the client's read half must survive its own close"),
            Some(expected.to_vec())
        );
    }
    assert_eq!(
        next_read(&ours, "client")
            .await
            .expect("read the server's FIN"),
        None
    );
    assert_nothing_accepted(&client, "data on a stream the client opened").await;

    wait_until_no_streams(&client, "client").await;
    wait_until_no_streams(&server, "server").await;
    shutdown(&client, &server).await;
}

/// Closing streams from both ends, over and over, leaves the stream table as it was.
///
/// Every stream left behind by a close counts against [`MAX_STREAMS`], and the cap is what
/// refuses a peer's new streams. So a table that grows by one per closed stream stops
/// accepting the peer's streams after a few hundred ordinary request/response exchanges,
/// and the segments it refuses are never acknowledged, which stalls the peer as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_closed_from_both_ends_do_not_use_up_the_stream_table() {
    const CYCLES: usize = MAX_STREAMS + 64;
    const WORKERS: usize = 16;

    let (client, server) = establish().await;

    // The server treats every stream the client opens the way an application that closes
    // on EOF does: read to the end, then close its own half.
    let responder = {
        let server = server.clone();
        tokio::spawn(async move {
            while let Ok(stream) = server.accept_stream().await {
                tokio::spawn(async move {
                    while let Ok(Some(_)) = stream.recv().await {}
                    let _ = stream.disconnect().await;
                });
            }
        })
    };

    let clean = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::with_capacity(WORKERS);
    for first in 0..WORKERS {
        let client = client.clone();
        let clean = clean.clone();
        workers.push(tokio::spawn(async move {
            for _ in (first..CYCLES).step_by(WORKERS) {
                let stream = client.open_stream();
                stream
                    .send_reliable(b"x".to_vec())
                    .await
                    .expect("send on a fresh stream");
                stream.disconnect().await.expect("close the client's half");
                // Read until the server's FIN. An error ends the wait too, so the pacing
                // holds whatever the read half does; how it ended is counted, and asserted
                // once the table itself has been checked.
                loop {
                    match timeout(STEP, stream.recv()).await {
                        Ok(Ok(Some(_))) => {}
                        Ok(Ok(None)) => {
                            clean.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        Ok(Err(_)) => break,
                        Err(_) => panic!(
                            "stream {} neither ended nor failed within {STEP:?}",
                            stream.stream_id()
                        ),
                    }
                }
            }
        }));
    }
    for worker in workers {
        worker.await.expect("worker task");
    }

    // After all of that, a stream the server opens is still one the client takes.
    let late = server.open_stream();
    late.send_reliable(b"after".to_vec())
        .await
        .expect("send on the server's new stream");
    let mut resurfaced = Vec::new();
    let deadline = Instant::now() + STEP;
    let fresh = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match timeout(left, client.accept_stream()).await {
            Ok(Ok(stream)) if stream.stream_id() == late.stream_id() => break Some(stream),
            Ok(Ok(stream)) => resurfaced.push(stream.stream_id()),
            _ => break None,
        }
    };
    let fresh = fresh.unwrap_or_else(|| {
        panic!(
            "after {CYCLES} streams closed from both ends the client never took the server's \
             new stream; {} stream(s) the client had opened and closed came back through \
             accept_stream instead",
            resurfaced.len()
        )
    });
    assert!(
        resurfaced.is_empty(),
        "{} stream(s) the client opened and closed came back through accept_stream, e.g. {:?}",
        resurfaced.len(),
        &resurfaced[..resurfaced.len().min(8)]
    );
    assert_eq!(
        next_read(&fresh, "client")
            .await
            .expect("read the new stream"),
        Some(b"after".to_vec())
    );
    assert_eq!(
        clean.load(Ordering::Relaxed),
        CYCLES,
        "every stream the client closed first must have gone on to read the server's EOF"
    );

    late.disconnect().await.expect("close the server's half");
    assert_eq!(next_read(&fresh, "client").await.expect("read EOF"), None);
    fresh.disconnect().await.expect("close the client's half");

    wait_until_no_streams(&client, "client").await;
    wait_until_no_streams(&server, "server").await;
    responder.abort();
    shutdown(&client, &server).await;
}

/// A write issued after a stream's own close does not reach the peer behind the EOF.
///
/// The FIN is the last thing on the stream by definition: the peer has already told its
/// application that nothing follows it. A write queued behind the close would be sent on
/// the next offset and delivered after that EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_after_close_does_not_follow_the_eof() {
    let (client, server) = establish().await;

    let ours = client.open_stream();
    ours.send_reliable(b"ping".to_vec())
        .await
        .expect("send ping");
    let theirs = accept(&server, "server").await;
    assert_eq!(
        next_read(&theirs, "server").await.expect("read ping"),
        Some(b"ping".to_vec())
    );

    ours.disconnect().await.expect("close the client's half");
    ours.send_reliable(b"after-close".to_vec())
        .await
        .expect("the command channel takes the write");

    assert_eq!(
        next_read(&theirs, "server")
            .await
            .expect("read the client's FIN"),
        None
    );
    if let Ok(read) = timeout(QUIET, theirs.recv()).await {
        panic!("the server read {read:?} after the client's EOF");
    }

    shutdown(&client, &server).await;
}
