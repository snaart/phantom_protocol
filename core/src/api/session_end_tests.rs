//! How a session ends, from the outside (test-only).
//!
//! Every defect pinned here is about the moment a session stops, and what a caller who was
//! in the middle of using it is told:
//!
//! * a [`PhantomStream::recv`] parked on a stream is released when the session ends,
//!   **after** whatever was already delivered into that stream — it used to wait for the
//!   life of the process, one task per stream, because nothing dropped the delivery routes;
//! * a peer's FIN still reads as end-of-stream exactly once, and the session's own end reads
//!   as a closed session rather than as a clean end of stream;
//! * an orderly close — this side's or the peer's — reports itself as one:
//!   [`CoreError::ConnectionClosed`] with nothing recorded against the session, against a
//!   `Dead` state and a recorded cause for a connection that broke. The two call for
//!   opposite reactions and used to be byte-for-byte identical at the surface;
//! * a close that arrives while the handshake is still running is not walked back by the
//!   handshake completing;
//! * one stream past the concurrency cap is refused, with the session and every other
//!   stream left alone — writing on it used to kill the whole session a few seconds later;
//! * letting go of a stream nothing was ever written on costs the session's pump nothing at
//!   all, so releasing handles is proportional to how many are released rather than to how
//!   many the session holds.
//!
//! The link is an in-memory pipe that can be **cut**: after the cut, reads report that the
//! byte pipe has ended and writes are quietly dropped, which is what a stream socket whose
//! far end vanished looks like from here — no protocol close, no error on the way out.
//!
//! The module is declared `#[cfg(test)]` in `api/mod.rs`, so it carries no inner
//! `#![cfg(test)]` of its own.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{timeout, Instant};

use crate::api::session::{ConnectionState, PhantomSession, SessionTransport, MAX_STREAMS};
use crate::api::stream::PhantomStream;
use crate::errors::CoreError;
use crate::transport::handshake::{ClientHello, HandshakeResponse, HandshakeServer, ServerReply};

/// Budget for a step that takes a few round trips. Generous, because what these tests are
/// about is waits that never end rather than waits that are slow.
const STEP: Duration = Duration::from_secs(10);
/// How long something that must not happen is given to happen.
const QUIET: Duration = Duration::from_millis(400);
/// Long enough to cover the peer-close draining window's 200 ms floor and its 600 ms
/// ceiling, so a session that ends because the peer said so has finished ending.
const AFTER_THE_DRAIN: Duration = Duration::from_millis(1200);

// ── A pipe that can be cut ───────────────────────────────────────────────────

/// What both ends of a [`Pipe`] pair watch to learn the link has been cut.
type Cut = watch::Receiver<bool>;

/// An in-memory duplex byte pipe, optionally cuttable.
///
/// It implements no part of the `SessionTransport` control surface beyond the two I/O
/// methods, and needs none: it is not a wrapper over another transport, so there is nothing
/// underneath it for a control call to have to reach.
struct Pipe {
    out: mpsc::Sender<Vec<u8>>,
    inbox: Mutex<mpsc::Receiver<Vec<u8>>>,
    cut: Cut,
}

impl Pipe {
    /// A connected pair, plus the switch that cuts the link for both of them.
    fn pair() -> (Self, Self, watch::Sender<bool>) {
        const DEPTH: usize = 4096;
        let (cut_tx, cut_rx) = watch::channel(false);
        let (a_tx, b_rx) = mpsc::channel(DEPTH);
        let (b_tx, a_rx) = mpsc::channel(DEPTH);
        (
            Self {
                out: a_tx,
                inbox: Mutex::new(a_rx),
                cut: cut_rx.clone(),
            },
            Self {
                out: b_tx,
                inbox: Mutex::new(b_rx),
                cut: cut_rx,
            },
            cut_tx,
        )
    }
}

/// What a read reports once the far end has gone: the byte pipe has ended, and it ended
/// without anybody saying anything about it.
fn vanished() -> CoreError {
    CoreError::NetworkError("the far end vanished".into())
}

impl SessionTransport for Pipe {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        if *self.cut.borrow() {
            // Dropped rather than refused, so that the only thing that ends the session is
            // the read side. A write that failed would end it too, by a different route,
            // and then the test would not be pinning the route it names.
            return Ok(());
        }
        self.out
            .send(data.to_vec())
            .await
            .map_err(|_| vanished())
            .map(|()| ())
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        // Exactly one reader per end (the pump's receive task), so holding the inbox is
        // never contended.
        let mut inbox = self.inbox.lock().await;
        let mut cut = self.cut.clone();
        tokio::select! {
            // `wait_for` inspects the current value first, so a cut that landed before this
            // call cannot be missed.
            _ = cut.wait_for(|c| *c) => Err(vanished()),
            got = inbox.recv() => got.map(Bytes::from).ok_or_else(vanished),
        }
    }
}

// ── Harness ──────────────────────────────────────────────────────────────────

/// Drive the server half of the handshake by hand and install a real
/// [`PhantomSession`] around the negotiated session, so both ends run the production pump.
async fn drive_server(server_hs: HandshakeServer, link: Pipe) -> Arc<PhantomSession> {
    let inner = negotiate(&server_hs, &link).await;
    PhantomSession::from_accepted_server_session("test-client".into(), link, Arc::new(inner))
}

/// Read the client's hello (answering the DoS gate's one cookie retry if it asks) and send
/// the `ServerHello`, returning the negotiated inner session.
async fn negotiate(server_hs: &HandshakeServer, link: &Pipe) -> crate::transport::session::Session {
    let client_ip = "127.0.0.1".parse().expect("parse IP");
    let mut bytes = link.recv_bytes().await.expect("recv ClientHello");
    loop {
        let hello = borsh::from_slice::<ClientHello>(&bytes).expect("deserialize ClientHello");
        match server_hs.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let wire = ServerReply::Retry(retry)
                    .to_wire()
                    .expect("serialize retry");
                link.send_bytes(&wire).await.expect("send retry");
                bytes = link.recv_bytes().await.expect("recv retry hello");
            }
            HandshakeResponse::Success(server_hello, session, _) => {
                let wire = ServerReply::Hello(server_hello)
                    .to_wire()
                    .expect("serialize ServerHello");
                link.send_bytes(&wire).await.expect("send ServerHello");
                return session;
            }
            HandshakeResponse::Reject(r) => panic!("unexpected Reject: {r:?}"),
            HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
        }
    }
}

/// A live client↔server pair over a cuttable pipe, and the switch that cuts it.
async fn establish() -> (
    Arc<PhantomSession>,
    Arc<PhantomSession>,
    watch::Sender<bool>,
) {
    let server_hs = HandshakeServer::new().expect("HandshakeServer::new");
    let pinned = server_hs.verifying_key().clone();
    let (client_link, server_link, cut) = Pipe::pair();
    let client = Arc::new(PhantomSession::connect_with_transport(
        "test-server:9000",
        client_link,
        pinned,
    ));
    let server = tokio::spawn(drive_server(server_hs, server_link));
    wait_for_state(&client, ConnectionState::Connected, "client").await;
    let server = server.await.expect("server task");
    (client, server, cut)
}

async fn wait_for_state(session: &PhantomSession, want: ConnectionState, who: &str) {
    let deadline = Instant::now() + STEP;
    while session.connection_state() != want {
        assert!(
            Instant::now() < deadline,
            "{who}: state is {:?}, waited for {want:?}",
            session.connection_state()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The next stream `session` accepts, which has to arrive within [`STEP`].
async fn accept(session: &PhantomSession) -> Arc<PhantomStream> {
    timeout(STEP, session.accept_stream())
        .await
        .expect("no stream was accepted")
        .expect("accept_stream")
}

/// One `recv()` on `stream` that must return — the whole point of most of this file.
async fn read(stream: &PhantomStream, who: &str) -> Result<Option<Vec<u8>>, CoreError> {
    timeout(STEP, stream.recv()).await.unwrap_or_else(|_| {
        panic!(
            "{who}: recv() on stream {} never returned",
            stream.stream_id()
        )
    })
}

// ── A reader parked on a stream is released when the session ends ────────────

/// A reader parked in [`PhantomStream::recv`] is released when the peer closes the session,
/// while this side still holds its session handle.
///
/// Nothing used to release it. The sender behind a stream's delivery channel lives in the
/// session's demultiplexer, which is owned by the `PhantomSession` — so as long as the
/// application held the session, the channel stayed open with nobody left to write to it,
/// and the read simply waited. Fifteen seconds after the path died the state already read
/// `Closed` and `PhantomSession::recv()` already returned an error, while this call was
/// still pending: one leaked task per stream, on the first disconnect a consumer sees.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parked_stream_reader_is_released_by_the_peers_close() {
    let (client, server, _cut) = establish().await;

    let ours = client.open_stream().expect("open a stream");
    ours.send_reliable(b"request".to_vec())
        .await
        .expect("send on a fresh stream");
    let theirs = accept(&server).await;
    assert_eq!(
        read(&theirs, "server").await.expect("the request"),
        Some(b"request".to_vec())
    );

    // Park a reader, then end the session from the other end.
    let parked = {
        let theirs = theirs.clone();
        tokio::spawn(async move { theirs.recv().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    client.disconnect().await.expect("disconnect");

    let released = timeout(STEP, parked)
        .await
        .expect("a reader parked in recv() was never released by the end of the session")
        .expect("reader task");
    assert!(
        matches!(released, Err(CoreError::ConnectionClosed)),
        "the end of a session with no FIN on this stream is a closed session, not a clean \
         end of stream; got {released:?}"
    );
    // The session handle is still held here, which is the point: the release cannot depend
    // on the application letting go of the session.
    assert_eq!(server.connection_state(), ConnectionState::Closed);
    drop(client);
}

/// What was already delivered into a stream is read before its end is reported.
///
/// This is the half that makes releasing the readers safe. Ending the channel is the only
/// way a reader learns anything, but a bounded channel hands out what is already in it
/// before it reports its end — so the frames that arrived just before the session stopped
/// are not the price of waking the reader up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_reader_drains_what_arrived_before_the_session_ended() {
    const FRAMES: usize = 8;

    let (client, server, _cut) = establish().await;

    let ours = client.open_stream().expect("open a stream");
    for i in 0..FRAMES {
        ours.send_reliable(vec![i as u8; 64])
            .await
            .expect("send on a fresh stream");
    }
    // Accept the stream but read nothing yet, so every frame is sitting in its channel when
    // the session ends.
    let theirs = accept(&server).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    client.disconnect().await.expect("disconnect");
    tokio::time::sleep(AFTER_THE_DRAIN).await;
    wait_for_state(&server, ConnectionState::Closed, "server").await;

    for i in 0..FRAMES {
        assert_eq!(
            read(&theirs, "server").await.expect("a buffered frame"),
            Some(vec![i as u8; 64]),
            "frame {i} was discarded by the session ending"
        );
    }
    assert!(
        matches!(
            read(&theirs, "server").await,
            Err(CoreError::ConnectionClosed)
        ),
        "the end comes after the buffered frames, not instead of them"
    );
    drop(client);
}

/// A peer's FIN reads as end-of-stream exactly once, and the stream's own end still reads as
/// a closed session afterwards.
///
/// The two answers mean different things and neither may stand in for the other. `Ok(None)`
/// says *this stream* was read to its end, which only a FIN establishes; the error says the
/// session is over and nobody can say whether it was. So the FIN is delivered once and not
/// again — a stream whose read half has ended but whose write half has not is still a live
/// stream, and a further read waits rather than reporting a second end — and when the
/// session does end, that waiting read is released with the error and not with another
/// `Ok(None)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_fin_reads_as_end_of_stream_once_and_then_as_a_closed_session() {
    let (client, server, _cut) = establish().await;

    let ours = client.open_stream().expect("open a stream");
    ours.send_reliable(b"last".to_vec())
        .await
        .expect("send on a fresh stream");
    ours.disconnect().await.expect("close the writing half");
    let theirs = accept(&server).await;

    assert_eq!(
        read(&theirs, "server").await.expect("the payload"),
        Some(b"last".to_vec())
    );
    assert_eq!(
        read(&theirs, "server").await.expect("the peer's FIN"),
        None,
        "a FIN is a clean end of stream"
    );

    // Once, not twice: this end's own half is still open, so the stream is not over.
    let again = {
        let theirs = theirs.clone();
        tokio::spawn(async move { theirs.recv().await })
    };
    tokio::time::sleep(QUIET).await;
    assert!(
        !again.is_finished(),
        "the peer's FIN was reported a second time on a stream this side had not closed"
    );

    // The session ending releases it, and as the error rather than as another clean end.
    client.disconnect().await.expect("disconnect");
    let released = timeout(STEP, again)
        .await
        .expect("the read past the FIN was never released")
        .expect("reader task");
    assert!(
        matches!(released, Err(CoreError::ConnectionClosed)),
        "got {released:?}"
    );

    drop(ours);
    drop(client);
}

/// A handshake that fails releases the streams the application opened while it ran.
///
/// The pump never starts on that path, so nothing else ever would: the streams and their
/// routes were built by `open_stream()` before the outcome was known, and a reader on one
/// of them waited for a session that never existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_handshake_releases_the_streams_opened_while_it_ran() {
    let server_hs = HandshakeServer::new().expect("HandshakeServer::new");
    let pinned = server_hs.verifying_key().clone();
    let (client_link, _server_link, cut) = Pipe::pair();
    let client = Arc::new(PhantomSession::connect_with_transport(
        "test-server:9000",
        client_link,
        pinned,
    ));

    // Opened while the handshake is still in flight, which is allowed and is exactly how a
    // consumer that connects and immediately opens a stream behaves.
    let ours = client.open_stream().expect("open a stream");
    let parked = {
        let ours = ours.clone();
        tokio::spawn(async move { ours.recv().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The far end vanishes: no ServerHello, ever.
    cut.send_replace(true);
    wait_for_state(&client, ConnectionState::Failed, "client").await;

    let released = timeout(STEP, parked)
        .await
        .expect("a reader on a stream of a session that never came up was never released")
        .expect("reader task");
    assert!(
        matches!(released, Err(CoreError::ConnectionClosed)),
        "got {released:?}"
    );
    assert!(
        client.last_error().await.is_some(),
        "a handshake that failed records why"
    );
    drop(ours);
}

// ── The concurrency cap ──────────────────────────────────────────────────────

/// Past [`MAX_STREAMS`] open at once, `open_stream()` refuses, and the refusal costs
/// nothing: no id spent out of a space that never reuses one, no route left behind, and the
/// next stream opened after one closes gets the id it would have got anyway.
///
/// Refusing at all is the fix. The peer holds the same limit on how many streams it will
/// take from us and enforces it *silently* — the segment that would open the stream is
/// never acknowledged — so the stream past the limit did not fail, it stalled with data
/// outstanding, and inbound silence with data in flight is what the liveness sweep reads as
/// a dead path. `open_stream()` returned `Ok`, `send_reliable()` returned `Ok`, nothing
/// reported the limit, and a few seconds later the whole session was gone.
///
/// Driven against an inert session, with no pump and no peer, because the cap is this
/// side's own arithmetic and nothing here should depend on a round trip.
#[tokio::test]
async fn open_stream_refuses_past_the_cap_without_spending_an_id() {
    let session = PhantomSession::connect("inert:0".into());

    let mut held = Vec::with_capacity(MAX_STREAMS);
    for i in 0..MAX_STREAMS {
        held.push(
            session
                .open_stream()
                .unwrap_or_else(|e| panic!("stream {i} of {MAX_STREAMS} was refused: {e:?}")),
        );
    }
    let last_id = held.last().expect("MAX_STREAMS is not zero").stream_id();
    assert_eq!(session.demux().active_stream_count(), MAX_STREAMS);

    for attempt in 0..3 {
        match session.open_stream() {
            Err(CoreError::StreamError(_)) => {}
            Err(other) => panic!("attempt {attempt}: refused with {other:?}"),
            Ok(extra) => panic!(
                "attempt {attempt}: handed out stream {} past the cap of {MAX_STREAMS}",
                extra.stream_id()
            ),
        }
        assert_eq!(
            session.demux().active_stream_count(),
            MAX_STREAMS,
            "attempt {attempt}: a refused open left a route behind"
        );
    }

    // One stream goes; the next one opens, and its id is the very next of this side's
    // parity — so none of the three refusals above spent one.
    held.pop();
    assert_eq!(session.demux().active_stream_count(), MAX_STREAMS - 1);
    let next = session.open_stream().expect("a slot has freed");
    assert_eq!(
        next.stream_id(),
        last_id + 2,
        "a refused open must not advance the id allocator"
    );
}

/// Every one of the [`MAX_STREAMS`] streams this side may open is surfaced by the peer.
///
/// The two halves of the limit have to agree, or the last stream this side is allowed to
/// open is one the peer will not take — which is the stall the refusal above exists to
/// avoid, and it was reachable: the peer charged its own reserved raw-application stream
/// against the peer's allowance, so it took `MAX_STREAMS - 1` and silently refused the
/// last.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_peer_takes_every_stream_the_cap_allows() {
    let (client, server, _cut) = establish().await;

    // Accept concurrently: the incoming-stream channel is bounded, and a handle that finds
    // it full is dropped rather than held for an application that is not asking.
    let collector = {
        let server = server.clone();
        tokio::spawn(async move {
            let mut taken: Vec<Arc<PhantomStream>> = Vec::with_capacity(MAX_STREAMS);
            while taken.len() < MAX_STREAMS {
                match timeout(STEP, server.accept_stream()).await {
                    Ok(Ok(stream)) => taken.push(stream),
                    _ => break,
                }
            }
            taken
        })
    };

    let mut ours = Vec::with_capacity(MAX_STREAMS);
    for i in 0..MAX_STREAMS {
        let stream = client
            .open_stream()
            .unwrap_or_else(|e| panic!("stream {i} of {MAX_STREAMS} was refused: {e:?}"));
        stream
            .send_reliable(vec![0xA5])
            .await
            .expect("send on a fresh stream");
        ours.push(stream);
    }

    let taken = timeout(Duration::from_secs(60), collector)
        .await
        .expect("the collector finished")
        .expect("collector task");
    assert_eq!(
        taken.len(),
        MAX_STREAMS,
        "the peer surfaced {} of the {MAX_STREAMS} streams the cap allows this side to open",
        taken.len()
    );
    // And the session is healthy afterwards: nothing was left stalling it.
    assert_eq!(client.connection_state(), ConnectionState::Connected);
    tokio::time::sleep(QUIET).await;
    assert_eq!(client.connection_state(), ConnectionState::Connected);
    assert!(client.last_error().await.is_none());

    drop(taken);
    drop(ours);
    client.disconnect().await.expect("disconnect");
    drop(client);
}
