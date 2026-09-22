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
//! * a stream the application only writes to cannot fill its own delivery channel with the
//!   acknowledgements of what it wrote, and so cannot stop delivery to the other streams;
//! * nothing written after a stream's own close reaches the peer behind its EOF;
//! * a stream whose handle this side has dropped closes its writing half behind what it
//!   wrote, and leaves the table once that close is acknowledged, whether or not the peer
//!   ever closes its own half — while a handle still held keeps its stream until it does;
//! * a peer still writing on a stream this side has let go of is granted room as well as
//!   acknowledged, so neither that stream nor the peer's others stop.
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
use crate::api::session::{
    ConnectionState, PhantomSession, MAX_STREAMS, STREAM_RECV_CHANNEL_DEPTH,
};
use crate::api::stream::PhantomStream;
use crate::errors::CoreError;
use crate::transport::mtu::MAX_APP_CHUNK;

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
/// been closed — from both ends, or from its own once its handle was let go of — and
/// dropped.
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
            "{who}: {open} stream(s) still open and {routed} still routed — a stream with \
             nothing left to carry was never dropped"
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

/// A stream the application only writes to does not stop delivery to the session's other
/// streams.
///
/// A stream's delivery channel is bounded and only its reader empties it. If every
/// acknowledgement of that stream's own writes were queued there too, an upload whose
/// application never reads would fill it with them; the delivery task, which serves every
/// stream of the session in turn, would then park for good on the next thing addressed to
/// that stream — here the peer's FIN — and nothing after it would reach any stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_that_is_only_written_to_does_not_stall_the_others() {
    /// More segments than one stream's delivery channel has slots, so one acknowledgement
    /// per segment would fill it.
    const SEGMENTS: usize = STREAM_RECV_CHANNEL_DEPTH + 256;
    let (client, server) = establish().await;

    let upload = client.open_stream();
    let total = SEGMENTS * MAX_APP_CHUNK;
    upload
        .send_reliable(vec![0x5A; total])
        .await
        .expect("queue the upload");
    let sink = accept(&server, "server").await;
    let mut received = 0;
    while received < total {
        match next_read(&sink, "server").await.expect("read the upload") {
            Some(bytes) => received += bytes.len(),
            None => panic!("EOF after {received} of {total} bytes"),
        }
    }

    // The server acknowledged each of those segments before its application read it, so
    // every acknowledgement is already on its way to the client, ahead of what follows.
    sink.disconnect()
        .await
        .expect("close the server's half of the upload");
    // The pump drains streams in id order, and the server's first stream would be id 2,
    // below the upload's 3: its data would leave ahead of the FIN and reach the client
    // before anything could stall. Spending id 2 puts the second stream after the upload,
    // so the FIN is the first of the two on the wire.
    let _spent = server.open_stream();
    let other = server.open_stream();
    assert!(other.stream_id() > upload.stream_id());
    other
        .send_reliable(b"elsewhere".to_vec())
        .await
        .expect("send on a second stream");

    let other_here = accept(&client, "client").await;
    assert_eq!(other_here.stream_id(), other.stream_id());
    let delivered = timeout(STEP, other_here.recv())
        .await
        .expect("delivery to a second stream stalled behind a stream the application never reads")
        .expect("recv on the second stream");
    assert_eq!(delivered, Some(b"elsewhere".to_vec()));
    assert_eq!(
        next_read(&upload, "client")
            .await
            .expect("the upload stream's channel holds the server's EOF"),
        None
    );

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

/// Streams this side closes and lets go of leave its table even when the peer never closes
/// its half of them, and the peer's new streams are still taken afterwards.
///
/// A stream is dropped once both of its halves are closed, and the peer's half is the
/// peer's to close. An application on that side that reads each stream to the end and
/// moves on without calling `disconnect()` used to leave every stream this side opened in
/// its table for the life of the session, each counted against [`MAX_STREAMS`] — so a few
/// hundred ordinary requests were enough for the session to refuse every stream the peer
/// opened next, and to leave their segments unacknowledged. Once this side's FIN is
/// acknowledged and its handle is gone, nobody here can write on the stream or read from
/// it any more, and it goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_the_peer_never_closes_leave_the_table_once_let_go() {
    // Below the cap, because the server holds every one of these open and its own table
    // has to take them all; the client's table is the one the late streams run into.
    const CYCLES: usize = MAX_STREAMS - 16;
    const WORKERS: usize = 16;
    const LATE: usize = 32;

    let (client, server) = establish().await;

    // The server reads every stream the client opens to the end and then keeps the handle
    // without closing its half, so nothing closes it on the server's behalf either.
    let held = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let responder = {
        let server = server.clone();
        let held = held.clone();
        tokio::spawn(async move {
            while let Ok(stream) = server.accept_stream().await {
                let held = held.clone();
                tokio::spawn(async move {
                    while let Ok(Some(_)) = stream.recv().await {}
                    held.lock().await.push(stream);
                });
            }
        })
    };

    let mut workers = Vec::with_capacity(WORKERS);
    for first in 0..WORKERS {
        let client = client.clone();
        workers.push(tokio::spawn(async move {
            for _ in (first..CYCLES).step_by(WORKERS) {
                let stream = client.open_stream();
                stream
                    .send_reliable(b"request".to_vec())
                    .await
                    .expect("send on a fresh stream");
                stream.disconnect().await.expect("close the client's half");
            }
        }));
    }
    for worker in workers {
        worker.await.expect("worker task");
    }

    wait_until_no_streams(&client, "client").await;
    let deadline = Instant::now() + STEP;
    while held.lock().await.len() < CYCLES {
        assert!(
            Instant::now() < deadline,
            "the server read {} of {CYCLES} streams to the end",
            held.lock().await.len()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The table having emptied, the streams the server opens now are all taken — past the
    // point where the cap would have refused them had the closed streams stayed.
    let mut late = Vec::with_capacity(LATE);
    for _ in 0..LATE {
        let stream = server.open_stream();
        stream
            .send_reliable(b"late".to_vec())
            .await
            .expect("send on the server's new stream");
        late.push(stream);
    }
    for _ in 0..LATE {
        let stream = accept(&client, "client").await;
        assert_eq!(
            stream.stream_id() % 2,
            0,
            "stream {} is one the client opened, back through accept_stream",
            stream.stream_id()
        );
        assert_eq!(
            next_read(&stream, "client")
                .await
                .expect("read a late stream"),
            Some(b"late".to_vec())
        );
    }

    responder.abort();
    shutdown(&client, &server).await;
}

/// A handle still held keeps its stream — read half and all — after its own close has been
/// acknowledged, for as long as the peer's half is open.
///
/// The counterpart of the test above: what lets a stream go early is that nobody is left
/// to read it, and an application that closed its writing half and is still waiting for
/// the reply is exactly somebody.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_handle_keeps_its_stream_until_the_peer_closes() {
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
    assert_eq!(
        next_read(&theirs, "server")
            .await
            .expect("read the client's FIN"),
        None
    );

    // The server acknowledged the FIN before its application read the EOF; this is ample
    // time for the acknowledgement to land.
    tokio::time::sleep(QUIET).await;
    assert!(
        client.demux().has_stream(ours.stream_id()),
        "the client dropped a stream whose handle it still holds, with the server's half open"
    );

    theirs
        .send_reliable(b"pong".to_vec())
        .await
        .expect("send the reply");
    theirs.disconnect().await.expect("close the server's half");
    assert_eq!(
        next_read(&ours, "client").await.expect("read the reply"),
        Some(b"pong".to_vec())
    );
    assert_eq!(
        next_read(&ours, "client")
            .await
            .expect("read the server's FIN"),
        None
    );

    wait_until_no_streams(&client, "client").await;
    wait_until_no_streams(&server, "server").await;
    shutdown(&client, &server).await;
}

/// Dropping a stream handle closes the stream's writing half behind everything the handle
/// wrote, and the stream then leaves the table although the peer never closes its half.
///
/// Before, a dropped handle closed nothing: the peer never read an EOF, and the stream stayed
/// in both tables for the life of the session. What the peer sends on it afterwards has
/// nobody to read it here; it is acknowledged and dropped, which the peer sees as its own
/// stream closing normally rather than as a stall.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_a_stream_handle_closes_its_writing_half_behind_what_it_wrote() {
    let (client, server) = establish().await;

    let ours = client.open_stream();
    let id = ours.stream_id();
    let payload: Vec<u8> = (0..64 * MAX_APP_CHUNK + 17).map(|i| i as u8).collect();
    ours.send_reliable(payload.clone())
        .await
        .expect("send the payload");
    drop(ours);

    let theirs = accept(&server, "server").await;
    assert_eq!(theirs.stream_id(), id);
    let mut received = Vec::with_capacity(payload.len());
    while let Some(bytes) = next_read(&theirs, "server")
        .await
        .expect("the server's read half must end cleanly")
    {
        received.extend_from_slice(&bytes);
    }
    assert_eq!(
        received.len(),
        payload.len(),
        "the EOF must follow every byte the handle wrote"
    );
    assert!(received == payload, "the payload arrived altered");

    // The server holds its handle and has not closed its half.
    wait_until_no_streams(&client, "client").await;

    // What the server sends now reaches no application, and its stream still closes: the
    // client acknowledges the write and the FIN on the id it let go of.
    theirs
        .send_reliable(b"to nobody".to_vec())
        .await
        .expect("send on the server's half");
    theirs.disconnect().await.expect("close the server's half");
    assert_nothing_accepted(&client, "a write on a stream the client let go of").await;
    wait_until_no_streams(&server, "server").await;

    shutdown(&client, &server).await;
}

/// A stream opened and dropped without a byte written leaves without a trace: the peer
/// never hears of it, and this side's table forgets it at once.
///
/// Nothing reaches the wire when a stream is opened; the peer learns of a stream from its
/// first segment. Announcing the close of one it never learned of would open it on the peer
/// only to end it, and surface it through `accept_stream()` as an empty stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_dropped_before_it_was_written_leaves_without_a_trace() {
    let (client, server) = establish().await;

    let unused = client.open_stream();
    assert!(client.demux().has_stream(unused.stream_id()));
    drop(unused);

    wait_until_no_streams(&client, "client").await;
    assert_nothing_accepted(&server, "a stream the client opened and dropped unused").await;

    shutdown(&client, &server).await;
}

/// Wait until `session` no longer routes `stream_id`: it has been dropped, which for a stream
/// whose handle is still held means both of its halves are closed and settled.
async fn wait_until_gone(session: &PhantomSession, stream_id: u32, who: &str) {
    let deadline = Instant::now() + STEP;
    while session.demux().has_stream(stream_id) {
        assert!(
            Instant::now() < deadline,
            "{who}: stream {stream_id} is still routed — what was written on it never settled"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Writes that must each be taken by the session, one after another: more than its command
/// channel holds, so a session that has stopped taking commands blocks one of these calls
/// rather than merely leaving the writes queued.
const WRITES_BEHIND: usize = 320;

/// `writer` opens a second stream of its own and writes a burst on it, behind whatever it has
/// queued already, and every byte of the burst has to reach `reader`.
///
/// Every one of the writer's `send_reliable` calls has to return, and the burst has to arrive
/// whole and in order. Nothing here is timed beyond the generous per-step budget: the failure
/// this guards against is a session that never takes the writes at all.
async fn a_second_stream_still_delivers(
    writer: &PhantomSession,
    reader: &PhantomSession,
    who: &str,
) {
    let other = writer.open_stream();
    let mut expected = Vec::new();
    for n in 0..WRITES_BEHIND {
        let message = format!("elsewhere {n};").into_bytes();
        expected.extend_from_slice(&message);
        timeout(STEP, other.send_reliable(message))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{who}: write {n} on a second stream did not return — the session stopped \
                     taking writes"
                )
            })
            .expect("write on a second stream");
    }
    let here = accept(reader, "reader").await;
    assert_eq!(here.stream_id(), other.stream_id());
    let mut received = Vec::with_capacity(expected.len());
    while received.len() < expected.len() {
        match next_read(&here, "reader")
            .await
            .expect("read the second stream")
        {
            Some(bytes) => received.extend_from_slice(&bytes),
            None => panic!("EOF after {} of {} bytes", received.len(), expected.len()),
        }
    }
    assert!(
        received == expected,
        "{who}: the second stream arrived altered"
    );
    other.disconnect().await.expect("close the second stream");
    assert_eq!(next_read(&here, "reader").await.expect("read EOF"), None);
    here.disconnect().await.expect("close the reader's half");
}

/// Bytes the peer writes on a stream this side has let go of: several times what one stream
/// can have outstanding — the most window this side ever grants, a full delivery queue, and
/// everything the peer's send buffer holds — so that a peer stopped at its last grant is left
/// holding writes it has nowhere to put.
const TO_NOBODY: usize = 8 * 1024 * 1024;

/// A stream this side lets go of while the peer is still writing on it does not stop the
/// peer's session.
///
/// Once this side's close of a stream it has let go of is acknowledged, the stream leaves the
/// table, and what the peer writes on it afterwards is acknowledged and discarded. But the
/// peer's writes are bounded by the flow-control limit this side grants, and a dropped stream
/// granted nothing more: the peer stopped at the last limit it had. Its refused writes then
/// sat at the head of the queue its session keeps for every stream, and while that queue
/// holds a write the session takes no further command — so every write on every other stream
/// of the peer's session waited behind the one stream nobody would ever read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_let_go_of_while_the_peer_writes_does_not_stall_the_peer() {
    let (client, server) = establish().await;

    let ours = client.open_stream();
    ours.send_reliable(b"open".to_vec())
        .await
        .expect("open the stream on the wire");
    let theirs = accept(&server, "server").await;
    assert_eq!(
        next_read(&theirs, "server").await.expect("read open"),
        Some(b"open".to_vec())
    );
    drop(ours);
    assert_eq!(
        next_read(&theirs, "server")
            .await
            .expect("the client's dropped handle closes its half"),
        None
    );
    // The client's close is acknowledged and nobody holds the stream, so it is gone from the
    // client's table before the server writes another byte on it.
    wait_until_no_streams(&client, "client").await;

    theirs
        .send_reliable(vec![0xA5; TO_NOBODY])
        .await
        .expect("write on the server's half");
    a_second_stream_still_delivers(&server, &client, "server").await;

    // And the writes on the stream the client let go of complete: the server's close follows
    // them in its send buffer, so the stream leaves the server's table only once every one of
    // them has been acknowledged.
    theirs.disconnect().await.expect("close the server's half");
    wait_until_gone(&server, theirs.stream_id(), "server").await;
    assert_nothing_accepted(&client, "a write on a stream the client let go of").await;
    assert_eq!(server.connection_state(), ConnectionState::Connected);
    assert_eq!(client.connection_state(), ConnectionState::Connected);

    shutdown(&client, &server).await;
}

/// The same, with the peer already stopped on this side's window when the handle is let go
/// of: the application here never read the stream, so the peer is waiting on the limit it was
/// last given, and the rest of what it writes arrives after the stream has left the table.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_let_go_of_mid_upload_does_not_stall_the_peer() {
    let (client, server) = establish().await;

    let ours = client.open_stream();
    ours.send_reliable(b"open".to_vec())
        .await
        .expect("open the stream on the wire");
    let theirs = accept(&server, "server").await;
    assert_eq!(
        next_read(&theirs, "server").await.expect("read open"),
        Some(b"open".to_vec())
    );

    // The client holds its handle and reads nothing, so the server fills the stream's
    // delivery queue and stops on the window the client granted for it.
    theirs
        .send_reliable(vec![0x5A; TO_NOBODY])
        .await
        .expect("write on the server's half");
    tokio::time::sleep(QUIET).await;
    drop(ours);
    wait_until_no_streams(&client, "client").await;

    a_second_stream_still_delivers(&server, &client, "server").await;

    theirs.disconnect().await.expect("close the server's half");
    wait_until_gone(&server, theirs.stream_id(), "server").await;
    assert_eq!(server.connection_state(), ConnectionState::Connected);
    assert_eq!(client.connection_state(), ConnectionState::Connected);

    shutdown(&client, &server).await;
}
