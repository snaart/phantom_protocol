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
        self.out.send(data.to_vec()).await.map_err(|_| vanished())
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

// ── An orderly end is not a failure, and a failure is not an orderly end ─────

/// An orderly close reaches the reader as a typed close with nothing recorded against the
/// session, and a byte pipe that ended without one reaches it as a death with a cause.
///
/// The two used to be byte-for-byte identical at the surface — `state=Closed`,
/// `last_error=None`, `recv=NetworkError("Session closed")`, `send=NetworkError("Cannot send
/// in state Closed")` — while calling for opposite reactions: take the result and stop,
/// against reconnect. `ConnectionState::Dead` and [`CoreError::ConnectionClosed`] both
/// existed and were documented for exactly this, and neither was reachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_orderly_close_and_a_broken_connection_are_told_apart() {
    // ── (a) the peer leaves in an orderly way ──
    let (client, server, _cut) = establish().await;
    client.send(b"hi".to_vec()).await.expect("send");
    assert_eq!(
        timeout(STEP, server.recv())
            .await
            .expect("recv")
            .expect("hi"),
        b"hi".to_vec()
    );
    client.disconnect().await.expect("disconnect");
    tokio::time::sleep(AFTER_THE_DRAIN).await;
    wait_for_state(&server, ConnectionState::Closed, "server").await;

    let orderly_recv = timeout(STEP, server.recv())
        .await
        .expect("recv returned")
        .expect_err("the session is over");
    assert!(
        matches!(orderly_recv, CoreError::ConnectionClosed),
        "an orderly peer close must reach the reader as a typed close; got {orderly_recv:?}"
    );
    assert!(
        server.last_error().await.is_none(),
        "nothing failed: the peer left"
    );
    let orderly_send = server
        .send(b"after".to_vec())
        .await
        .expect_err("a closed session takes no writes");
    assert!(
        matches!(orderly_send, CoreError::ConnectionClosed),
        "got {orderly_send:?}"
    );
    drop(client);

    // ── (b) the connection breaks under a live session ──
    let (client, server, cut) = establish().await;
    client.send(b"hi".to_vec()).await.expect("send");
    assert_eq!(
        timeout(STEP, server.recv())
            .await
            .expect("recv")
            .expect("hi"),
        b"hi".to_vec()
    );
    cut.send_replace(true);
    wait_for_state(&client, ConnectionState::Dead, "client").await;

    let broken_recv = timeout(STEP, client.recv())
        .await
        .expect("recv returned")
        .expect_err("the connection is gone");
    let cause = client
        .last_error()
        .await
        .expect("a connection that broke records why");
    assert!(
        !matches!(cause, CoreError::ConnectionClosed),
        "a broken connection must not report itself as an orderly close; got {cause:?}"
    );
    assert!(
        matches!(broken_recv, CoreError::NetworkError(_)),
        "the reader gets the cause the transport failed with; got {broken_recv:?}"
    );
    drop(server);
}

/// A session the caller closed itself reports no failure — anywhere.
///
/// `last_error()` returns `None`, which the crate documents as meaning nothing went wrong.
/// `await_ready()` used to synthesise `NetworkError("session failed")` alongside it, and
/// `send()` a formatted state name, so the two disagreed about the same session and neither
/// gave a caller anything to match on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_the_caller_asked_for_is_not_a_failure() {
    let (client, server, _cut) = establish().await;
    client.disconnect().await.expect("disconnect");

    assert!(
        client.last_error().await.is_none(),
        "the caller's own close is not a failure"
    );
    assert_eq!(client.connection_state(), ConnectionState::Closed);
    let ready = timeout(STEP, client.await_ready())
        .await
        .expect("await_ready returned")
        .expect_err("a closed session is not ready");
    assert!(
        matches!(ready, CoreError::ConnectionClosed),
        "got {ready:?}"
    );
    let write = client
        .send(b"late".to_vec())
        .await
        .expect_err("a closed session takes no writes");
    assert!(
        matches!(write, CoreError::ConnectionClosed),
        "got {write:?}"
    );
    drop(server);
}

/// A session that never tried is not reported as closed.
///
/// The typed close is a statement about a session that ran and ended, so it is not the
/// answer for the inert `connect()`, which builds no transport and runs no handshake and
/// reports `Failed` from the moment it returns. Nothing was recorded against it either —
/// nothing failed, because nothing happened — so it is the one session for which "ended with
/// no cause" must keep the generic answer rather than borrow a close that never occurred.
#[tokio::test]
async fn a_session_that_never_tried_is_not_reported_as_closed() {
    let session = PhantomSession::connect("inert:0".into());
    assert_eq!(session.connection_state(), ConnectionState::Failed);
    assert!(
        session.last_error().await.is_none(),
        "the inert constructor records no cause"
    );

    let ready = timeout(STEP, session.await_ready())
        .await
        .expect("await_ready must resolve at once on a session with no pump")
        .expect_err("an inert session is not ready");
    assert!(
        !matches!(ready, CoreError::ConnectionClosed),
        "a session that never opened has not been closed; got {ready:?}"
    );
    let write = session
        .send(b"never".to_vec())
        .await
        .expect_err("an inert session takes no writes");
    assert!(
        !matches!(write, CoreError::ConnectionClosed),
        "got {write:?}"
    );
}

// ── A close that arrives while the handshake runs ────────────────────────────

/// A close that lands while the handshake is still running is not walked back by what the
/// handshake does next — whichever way it goes.
///
/// The handshake is asynchronous, so `disconnect()` — or dropping the handle — can happen
/// while it is in flight, and it publishes `Closed` from the caller's own thread. Both of the
/// handshake's exits then wrote over that unconditionally, and both were wrong in their own
/// way:
///
/// * the **success** exit stored `Connected` and published it as the readiness answer, so
///   `await_ready()` said `Ok(())` for a session the caller had already closed, and a poller
///   saw it go live after being told to stop;
/// * the **failure** exit stored `Failed` *and recorded a cause*, so a session the caller
///   closed itself reported `state = Failed, last_error = Some(NetworkError("the far end
///   vanished"))` — a failure, about an event after the caller was done, in place of the
///   orderly end this release advertises.
///
/// Which exit runs is `handshake_succeeds`: the reply is composed either way and then either
/// sent or withheld while the link is cut, so both arms are the same race with the same
/// timing and differ only in what the handshake concludes. The failure arm exists because
/// the one that shipped covered only the success arm — the two exits are separate statements
/// about the same atomic, and fixing one says nothing about the other. Without it the next
/// edit to the failure arm reintroduces a bare `store` and nothing notices: the state is
/// correct for every session that was *not* closed during its handshake, which is all of
/// them in every other test.
async fn a_close_during_the_handshake_is_not_walked_back(handshake_succeeds: bool) {
    let server_hs = HandshakeServer::new().expect("HandshakeServer::new");
    let pinned = server_hs.verifying_key().clone();
    let (client_link, server_link, cut) = Pipe::pair();
    let client = Arc::new(PhantomSession::connect_with_transport(
        "test-server:9000",
        client_link,
        pinned,
    ));

    // Take the hello and compose the reply WITHOUT sending it, so the handshake is provably
    // still running when the close below lands.
    let (reply, inner) = compose_reply_without_sending(&server_hs, &server_link).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        client.connection_state(),
        ConnectionState::Connecting,
        "precondition: the handshake has not finished"
    );

    client.disconnect().await.expect("disconnect");
    assert_eq!(client.connection_state(), ConnectionState::Closed);

    // Watch for the state moving off the close while the handshake resolves behind us.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let poller = {
        let client = client.clone();
        let seen = seen.clone();
        tokio::spawn(async move {
            let until = Instant::now() + Duration::from_millis(600);
            while Instant::now() < until {
                seen.lock().await.push(client.connection_state());
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };
    if handshake_succeeds {
        // Release the reply: the client's handshake now succeeds.
        server_link
            .send_bytes(&reply)
            .await
            .expect("send ServerHello");
    } else {
        // Withhold it and cut the link instead: the client's read fails, so the handshake
        // ends in its failure arm with a cause of its own to record.
        cut.send_replace(true);
    }
    poller.await.expect("poller task");

    let ready = timeout(STEP, client.await_ready())
        .await
        .expect("await_ready returned")
        .expect_err("a session closed before it came up is not ready");
    assert!(
        matches!(ready, CoreError::ConnectionClosed),
        "the readiness answer has to be the close the caller asked for; got {ready:?}"
    );
    assert!(
        client.last_error().await.is_none(),
        "the caller's own close is not a failure; last_error() gave {:?}",
        client.last_error().await
    );
    assert_eq!(
        client.connection_state(),
        ConnectionState::Closed,
        "the close the caller asked for is the end this session reached"
    );
    let seen = seen.lock().await;
    for walked_back in [ConnectionState::Connected, ConnectionState::Failed] {
        assert!(
            !seen.contains(&walked_back),
            "the session was published as {walked_back:?} after the caller closed it: {seen:?}"
        );
    }
    drop(inner);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_during_a_handshake_that_then_succeeds_is_not_walked_back() {
    a_close_during_the_handshake_is_not_walked_back(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_during_a_handshake_that_then_fails_is_not_walked_back() {
    a_close_during_the_handshake_is_not_walked_back(false).await;
}

/// Read the client's hello (answering the DoS gate's cookie retry, which *is* sent) and
/// return the serialized `ServerHello` **unsent**, so the caller decides when the client's
/// handshake completes.
async fn compose_reply_without_sending(
    server_hs: &HandshakeServer,
    link: &Pipe,
) -> (Vec<u8>, crate::transport::session::Session) {
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
                return (
                    ServerReply::Hello(server_hello)
                        .to_wire()
                        .expect("serialize ServerHello"),
                    session,
                );
            }
            HandshakeResponse::Reject(r) => panic!("unexpected Reject: {r:?}"),
            HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
        }
    }
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

// ── Releasing handles ────────────────────────────────────────────────────────

/// Two samples of [`drain_passes`] this far apart, and the most the second may exceed the
/// first by for the send loop to count as having nothing of its own to do.
///
/// The 10 ms heartbeat drains unconditionally, so an idle pump still makes three passes in
/// this interval; anything much above that is the pump with work in hand — the pacer wakes it
/// as often as every millisecond while it has something to send, which is most of what it
/// does under load.
const QUIET_SAMPLE: Duration = Duration::from_millis(30);
const QUIET_PASSES: u64 = 5;

/// Wait until the send loop has nothing of its own left to do, so that what it does next can
/// be attributed to what the test does next.
async fn wait_until_quiet(session: &PhantomSession) {
    let deadline = Instant::now() + STEP;
    loop {
        let before = drain_passes(session).await;
        tokio::time::sleep(QUIET_SAMPLE).await;
        let delta = drain_passes(session).await - before;
        if delta <= QUIET_PASSES {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the send loop never went quiet: {delta} passes in {QUIET_SAMPLE:?}"
        );
    }
}

/// Total drain passes the send loop has made, whatever each of them stopped on. One pass
/// costs a walk over every stream the session holds, which is what made releasing handles
/// cost time quadratic in their number.
async fn drain_passes(session: &PhantomSession) -> u64 {
    session
        .bandwidth_snapshot()
        .await
        .expect("an established session has an estimator")
        .drain_outcomes
        .iter()
        .sum()
}

/// Letting go of a stream nothing was ever written on costs the session's pump nothing: the
/// stream is out of both tables before `drop` returns, and the send loop makes no pass at
/// all on its account.
///
/// That is what makes releasing handles proportional to how many are released. It used to
/// go to the pump like any other release, and each one cost a wake-up — and a wake-up costs
/// the send loop a walk over every stream the session holds, so four times the handles cost
/// twenty-one times the time, and for as long as the backlog lasted the peer's own streams
/// were refused.
///
/// The count deliberately exceeds [`MAX_STREAMS`]: a slot freed as the handle is dropped is
/// what lets a caller open and let go of streams in a loop without ever reaching the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn letting_go_of_an_unused_stream_costs_the_pump_nothing() {
    const CYCLES: usize = 4 * MAX_STREAMS;

    let (client, server, _cut) = establish().await;
    let before = drain_passes(&client).await;

    for i in 0..CYCLES {
        let stream = client
            .open_stream()
            .unwrap_or_else(|e| panic!("open {i} of {CYCLES}: {e:?}"));
        assert!(client.demux().has_stream(stream.stream_id()));
        let id = stream.stream_id();
        drop(stream);
        // No await between the drop and these two reads: whatever releases the stream has
        // to have done it by the time `drop` returned.
        assert!(
            !client.demux().has_stream(id),
            "stream {id} still had a route after its only handle was dropped"
        );
        assert_eq!(
            client.observability().snapshot().active_streams,
            0,
            "stream {id} was still counted open after its only handle was dropped"
        );
    }

    // The send loop is allowed to have run for its own reasons — the 10 ms heartbeat drains
    // unconditionally — but not once per stream. A pass per release is the shape being
    // ruled out, and CYCLES/4 separates that from any amount of heartbeat.
    let passes = drain_passes(&client).await - before;
    assert!(
        passes < (CYCLES / 4) as u64,
        "{CYCLES} released streams cost the send loop {passes} passes; a pass per release is \
         the cost this is here to rule out"
    );

    client.disconnect().await.expect("disconnect");
    drop(server);
}

/// A burst of released handles on streams that *were* written on is taken in batches, not
/// one send-loop pass apiece.
///
/// These cannot go the way the unused ones do — each has a close to send, behind the writes
/// its handle queued — so they do travel to the pump. What the pump must not do is come
/// back through its whole stream table once per handle.
///
/// **What the bar is made of**, since a pass count is not a constant of nature. The streams
/// are written on *unreliably*, which is what puts the release on the pump's path — the
/// handle has used its command channel, so its report cannot be acted on until the pump has
/// taken those commands in — while leaving the pump with nothing to send when the reports
/// arrive: an unreliable write is long gone, and a stream no reliable byte ever went out on
/// has no close to send either. So in the window measured below the send loop has no work of
/// its own, and the only things that can make it run are its 10 ms heartbeat and a wake-up
/// caused by a release. The window is fixed rather than "until the table empties", so the
/// heartbeat's share is a known `WINDOW / 10 ms` rather than something that grows with
/// however long the burst takes. A pass per release would be the burst itself, an order of
/// magnitude away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_released_streams_is_not_a_pass_each() {
    const BURST: usize = MAX_STREAMS / 2;
    /// Long enough for the pump to act on every report — one pass per release is a few
    /// milliseconds of work at this stream count — and short enough that the heartbeat's
    /// share of the count is a handful.
    const WINDOW: Duration = Duration::from_millis(50);

    let (client, server, _cut) = establish().await;
    // Somebody has to take the peer's streams, or their handles are dropped on arrival and
    // the server closes its halves for its own reasons.
    let collector = {
        let server = server.clone();
        tokio::spawn(async move {
            let mut taken: Vec<Arc<PhantomStream>> = Vec::new();
            while let Ok(Ok(stream)) = timeout(Duration::from_secs(5), server.accept_stream()).await
            {
                taken.push(stream);
            }
            taken
        })
    };

    let mut ours = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        let stream = client.open_stream().expect("open a stream");
        stream
            .send_unreliable(b"request".to_vec())
            .await
            .expect("send on a fresh stream");
        ours.push(stream);
    }
    // Let the writes go, so that when the reports below arrive the send loop has nothing of
    // its own left to do and every pass it makes is either its heartbeat or a release. Waited
    // for rather than assumed: the pacer wakes the pump as often as every millisecond while
    // it has anything to send, which would swamp what is counted below.
    wait_until_quiet(&client).await;

    let before = drain_passes(&client).await;
    drop(ours);
    tokio::time::sleep(WINDOW).await;
    let passes = drain_passes(&client).await - before;
    // What a quiet pump makes in this window, by the definition waited for above, plus one
    // pass for the batch and a few for the scheduling around it.
    let bar = QUIET_PASSES * (WINDOW.as_millis() / QUIET_SAMPLE.as_millis()) as u64 + 8;
    assert!(
        passes <= bar,
        "a burst of {BURST} released streams cost the send loop {passes} passes against a bar \
         of {bar} (the heartbeat's share of the window, plus the batch and some slack); \
         taking the reports one pump turn apiece is the shape this rules out, and it costs \
         about {BURST}"
    );

    // And they really were acted on: the table empties.
    let deadline = Instant::now() + STEP;
    while client.observability().snapshot().active_streams > 0 {
        assert!(
            Instant::now() < deadline,
            "{} of {BURST} released streams were never dropped",
            client.observability().snapshot().active_streams
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    collector.abort();
    client.disconnect().await.expect("disconnect");
    drop(server);
}

// ── Every resolved address is tried ──────────────────────────────────────────

/// A name that resolves to a black hole before it resolves to the server still connects.
///
/// The resolver's order is not a statement about what is reachable: `localhost` commonly
/// resolves to `::1` ahead of `127.0.0.1`, and a server listening only on IPv4 was then never
/// reached, because only the first address was ever used. Nothing reported it either — the
/// TCP helper works on the same name, since `TcpStream::connect` walks the list, while
/// "connecting" a datagram socket only records where to send and succeeds against an address
/// with nothing behind it. The failure surfaced much later as a handshake that timed out.
///
/// The budget here is the one knob the production entry points hand over: the whole call is
/// bounded by it, divided between the candidates, rather than each candidate getting the
/// whole of it.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_resolved_address_is_tried_until_one_answers() {
    use crate::api::session::connect_udp_trying_each_address;
    use crate::api::udp_listener::PhantomUdpListener;
    use crate::crypto::hybrid_sign::HybridVerifyingKey;

    /// Enough for a loopback handshake many times over, so a candidate that does not answer
    /// is the only reason an attempt can fail — and, split between the two candidates below,
    /// still above the floor the share is held at, so this test goes on exercising the
    /// division rather than the floor. `a_slow_but_working_first_address_is_not_abandoned`
    /// covers the floor.
    const BUDGET: Duration = Duration::from_secs(5);

    let listener = PhantomUdpListener::builder("127.0.0.1:0")
        .bind()
        .await
        .expect("bind a PhantomUDP listener");
    let live: std::net::SocketAddr = listener
        .local_addr()
        .parse()
        .expect("the listener's address");
    let pinned = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes())
        .expect("the listener's verifying key");

    // A bound socket nobody reads: datagrams reach it and nothing ever comes back, which is
    // exactly what an address in the wrong family looks like from a connected UDP socket.
    let hole = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a black hole");
    let hole_addr = hole.local_addr().expect("the black hole's address");

    // The black hole first. The live address is reached only if the list is walked.
    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.accept().await })
    };
    let session = {
        let pinned = pinned.clone();
        connect_udp_trying_each_address(
            "black-hole-first",
            &[hole_addr, live],
            BUDGET,
            move |transport| {
                PhantomSession::connect_with_transport(
                    "black-hole-first",
                    transport,
                    pinned.clone(),
                )
            },
        )
        .await
        .expect("one of the two addresses answers")
    };
    timeout(STEP, session.await_ready())
        .await
        .expect("await_ready returned")
        .expect("the live address answered");
    let accepted = timeout(STEP, accepting)
        .await
        .expect("the listener accepted")
        .expect("accept task")
        .expect("accept");
    assert_eq!(
        accepted.session().connection_state(),
        ConnectionState::Connected
    );
    session.disconnect().await.expect("disconnect");

    // The live address first: taken on the first attempt, with no wasted share.
    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.accept().await })
    };
    let started = Instant::now();
    let session = {
        let pinned = pinned.clone();
        connect_udp_trying_each_address(
            "live-first",
            &[live, hole_addr],
            BUDGET,
            move |transport| {
                PhantomSession::connect_with_transport("live-first", transport, pinned.clone())
            },
        )
        .await
        .expect("the first address answers")
    };
    timeout(STEP, session.await_ready())
        .await
        .expect("await_ready returned")
        .expect("the live address answered");
    assert!(
        started.elapsed() < BUDGET,
        "a first address that answers must not cost a whole share; took {:?}",
        started.elapsed()
    );
    let _ = timeout(STEP, accepting)
        .await
        .expect("the listener accepted");
    session.disconnect().await.expect("disconnect");

    // One address, which happens to be a black hole: handed back without waiting, exactly as
    // these entry points document — `Ok` here says a socket was bound and nothing more.
    let started = Instant::now();
    let session =
        connect_udp_trying_each_address("hole-only", &[hole_addr], BUDGET, move |transport| {
            PhantomSession::connect_with_transport("hole-only", transport, pinned.clone())
        })
        .await
        .expect("a single address is handed back unawaited");
    assert!(
        started.elapsed() < BUDGET,
        "the only candidate must be returned without waiting on its handshake; took {:?}",
        started.elapsed()
    );
    assert_eq!(session.connection_state(), ConnectionState::Connecting);
    drop(session);
    listener.shutdown();
}

/// A UDP relay that carries one client's datagrams to `upstream` and back, holding each of
/// them for `hop` on the way.
///
/// It exists to make a **slow but working** address, which loopback otherwise cannot produce:
/// every defect about per-candidate budgets is invisible at a microsecond round trip, because
/// any budget at all is enough there. Strictly one client and one upstream.
///
/// Each direction is a reader and a writer over a queue, and the writer sleeps until each
/// datagram's *own* arrival plus `hop` rather than sleeping `hop` per datagram in the reading
/// loop. That distinction is the whole design: a `ClientHello` does not fit in one datagram
/// (the ML-KEM encapsulation key alone is 1184 bytes against a 1200-byte path MTU), so it
/// arrives as several fragments, and a delay taken inline in the reader would charge `hop`
/// for each of them in turn — a three-fragment flight would cross in 1.2 s instead of 400 ms,
/// which is a different path than the one being modelled and, as first written, one whose
/// handshake fell outside the window this test needs. Sleeping to a per-datagram deadline
/// makes the one-way delay exactly `hop` whatever the fragment count, and preserves arrival
/// order for free: arrivals are ordered, so their deadlines are too.
#[cfg(not(target_arch = "wasm32"))]
async fn delaying_relay(
    front: tokio::net::UdpSocket,
    upstream: std::net::SocketAddr,
    hop: Duration,
) {
    /// One datagram waiting to be forwarded, with the moment it arrived.
    type Queued = (Instant, Vec<u8>);

    let front = Arc::new(front);
    let Ok(back) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
        return;
    };
    let back = Arc::new(back);
    if back.connect(upstream).await.is_err() {
        return;
    }
    // The client's address, learned from its first datagram. It always precedes anything
    // coming back, so the downstream writer below never has to wait for it.
    let (seen_tx, seen_rx) = watch::channel::<Option<std::net::SocketAddr>>(None);
    let (upward_tx, mut upward_rx) = mpsc::unbounded_channel::<Queued>();
    let (downward_tx, mut downward_rx) = mpsc::unbounded_channel::<Queued>();

    let from_client = {
        let front = front.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = front.recv_from(&mut buf).await {
                seen_tx.send_replace(Some(from));
                if upward_tx.send((Instant::now(), buf[..n].to_vec())).is_err() {
                    return;
                }
            }
        })
    };
    let to_upstream = {
        let back = back.clone();
        tokio::spawn(async move {
            while let Some((arrived, bytes)) = upward_rx.recv().await {
                tokio::time::sleep_until(arrived + hop).await;
                if back.send(&bytes).await.is_err() {
                    return;
                }
            }
        })
    };
    let from_upstream = {
        let back = back.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok(n) = back.recv(&mut buf).await {
                if downward_tx
                    .send((Instant::now(), buf[..n].to_vec()))
                    .is_err()
                {
                    return;
                }
            }
        })
    };

    while let Some((arrived, bytes)) = downward_rx.recv().await {
        tokio::time::sleep_until(arrived + hop).await;
        let to = *seen_rx.borrow();
        let Some(to) = to else {
            continue;
        };
        if front.send_to(&bytes, to).await.is_err() {
            break;
        }
    }
    from_client.abort();
    to_upstream.abort();
    from_upstream.abort();
}

/// A first address that is reachable but slow is not abandoned part-way through a handshake
/// that was going to succeed.
///
/// **The defect.** The per-candidate share was `budget / n` with no floor, so a name with
/// eight A/AAAA records — ordinary for a CDN or a multi-homed host — gave each candidate
/// 1.25 s of the ten-second client handshake deadline, while a PhantomUDP handshake needs the
/// cookie round plus hello/ServerHello: about 1.8 s on a 600 ms path. The first address was
/// correct and answering, and the walk dropped it, working session and all.
///
/// **What a consumer sees.** `connect_pinned_udp` against a multi-homed name hands back
/// whichever address happens to be last in the resolver's answer, on a path where 0.3.0
/// connected to the first. If the last one is a black hole — which is the case the walk was
/// written for — the connect fails outright.
///
/// **Why it comes back unnoticed.** Loopback. At a microsecond round trip every share is
/// enough, so the whole in-tree end-to-end coverage of the walk passes with any divisor at
/// all, and the arithmetic has no other output: a share that is too short is
/// indistinguishable at the surface from an address that did not answer. The relay above is
/// what makes the case reachable without a second host.
///
/// The two assertions are a pair and neither is enough alone. `spawned == 1` says the first
/// candidate was the only one ever attempted, so it was not abandoned — that is the fix.
/// `took > naive` says the handshake really did outlast the share the defect would have
/// handed out, so the test is exercising the case and not passing because the handshake got
/// fast.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_but_working_first_address_is_not_abandoned() {
    use crate::api::session::{
        connect_udp_trying_each_address, CLIENT_HANDSHAKE_DEADLINE, MIN_CANDIDATE_HANDSHAKE_SHARE,
    };
    use crate::api::udp_listener::PhantomUdpListener;
    use crate::crypto::hybrid_sign::HybridVerifyingKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// One-way delay the relay adds. A cookie-gated handshake is two flights, so it crosses
    /// the relay four times and takes about 1.4 s.
    ///
    /// That has to land between the share the defect handed out (`naive`, asserted below) and
    /// the floor, and the two margins are not symmetric in what threatens them. The lower one
    /// cannot be crossed at all: the relay's sleeps can only overshoot, so the handshake is
    /// never faster than `4 × HOP`. The upper one is what a loaded machine eats into, so the
    /// address count below is chosen to leave it the larger of the two — 600 ms against
    /// 400 ms.
    const HOP: Duration = Duration::from_millis(350);
    /// How many addresses the name has. Enough that the even division falls well under the
    /// floor, which is also what buys the margin described above.
    const ADDRESSES: usize = 10;

    let listener = PhantomUdpListener::builder("127.0.0.1:0")
        .bind()
        .await
        .expect("bind a PhantomUDP listener");
    let live: std::net::SocketAddr = listener
        .local_addr()
        .parse()
        .expect("the listener's address");
    let pinned = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes())
        .expect("the listener's verifying key");

    let front = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the relay's front socket");
    let relay_addr = front.local_addr().expect("the relay's address");
    let relay = tokio::spawn(delaying_relay(front, live, HOP));

    // Bound sockets nobody reads, held for the test's life so the ports stay taken. They are
    // here only to make the name an eight-address one; the walk must never reach them.
    let mut holes = Vec::new();
    let mut candidates = vec![relay_addr];
    for _ in 1..ADDRESSES {
        let hole = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind a black hole");
        candidates.push(hole.local_addr().expect("the black hole's address"));
        holes.push(hole);
    }

    let naive = CLIENT_HANDSHAKE_DEADLINE / ADDRESSES as u32;
    assert!(
        naive < MIN_CANDIDATE_HANDSHAKE_SHARE,
        "this test needs an address count whose even share ({naive:?}) is under the floor \
         ({MIN_CANDIDATE_HANDSHAKE_SHARE:?}), or it is not testing the floor"
    );

    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.accept().await })
    };
    let spawned = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let session =
        connect_udp_trying_each_address("slow-first", &candidates, CLIENT_HANDSHAKE_DEADLINE, {
            let pinned = pinned.clone();
            let spawned = spawned.clone();
            move |transport| {
                spawned.fetch_add(1, Ordering::Relaxed);
                PhantomSession::connect_with_transport("slow-first", transport, pinned.clone())
            }
        })
        .await
        .expect("the slow first address answers");
    timeout(STEP, session.await_ready())
        .await
        .expect("await_ready returned")
        .expect("the slow first address completed its handshake");
    let took = started.elapsed();

    assert_eq!(
        spawned.load(Ordering::Relaxed),
        1,
        "the walk made {} attempts, so the slow first address was abandoned before its \
         handshake finished",
        spawned.load(Ordering::Relaxed)
    );
    assert!(
        took > naive,
        "the handshake finished in {took:?}, inside the {naive:?} share the unfloored \
         division would have given it — so this run proves nothing about the floor. Raise \
         HOP or ADDRESSES."
    );

    let accepted = timeout(STEP, accepting)
        .await
        .expect("the listener accepted")
        .expect("accept task")
        .expect("accept");
    assert_eq!(
        accepted.session().connection_state(),
        ConnectionState::Connected
    );

    session.disconnect().await.expect("disconnect");
    relay.abort();
    listener.shutdown();
    drop(holes);
}

/// An address that answers for the name and is not the pinned server is reported to the
/// caller, and the walk stops there.
///
/// **The defect.** The walk recorded every candidate's `await_ready()` error into one slot and
/// discarded it the moment a later candidate succeeded, so `CoreError::ServerIdentityMismatch`
/// was treated exactly like "this address did not answer": a `log::debug!` line, and nothing
/// returned.
///
/// **What a consumer sees.** An attacker who gets one extra address into the DNS answer for
/// the server's name — an added AAAA record, a poisoned resolver, a hostile split-horizon
/// zone — is contacted *first* on every `connect_pinned_udp*` and receives the client's whole
/// `ClientHello`, and on `connect_pinned_udp_with_resumption` the sealed `early_data` blob as
/// well. The client then reaches the genuine address, returns `Ok`, and `await_ready()`
/// answers `Ok(())`. Confidentiality holds — the pin held and the blob stayed sealed — but
/// nothing tells the caller that an impostor answered for this name, in the one path
/// Invariant 1 exists to guarantee. At 0.3.0, with one address per name, the mismatch reached
/// the caller.
///
/// **Why it comes back unnoticed.** Swallowing a refusal makes the walk *more* likely to
/// reach a working address, so every functional test of it keeps passing — the only
/// difference is an error that is never raised, and nothing that passes looks for one. It is
/// also in the file `CONTRIBUTING.md` puts behind codeowner review, where the reviewer's
/// attention is on the crypto rather than on which arm of a `match` drops a value.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_impostor_answering_first_for_the_name_is_reported_and_stops_the_walk() {
    use crate::api::session::{connect_udp_trying_each_address, CLIENT_HANDSHAKE_DEADLINE};
    use crate::api::udp_listener::PhantomUdpListener;
    use crate::crypto::hybrid_sign::HybridVerifyingKey;

    let impostor = PhantomUdpListener::builder("127.0.0.1:0")
        .bind()
        .await
        .expect("bind the impostor");
    let genuine = PhantomUdpListener::builder("127.0.0.1:0")
        .bind()
        .await
        .expect("bind the genuine listener");
    let impostor_addr: std::net::SocketAddr = impostor
        .local_addr()
        .parse()
        .expect("the impostor's address");
    let genuine_addr: std::net::SocketAddr = genuine
        .local_addr()
        .parse()
        .expect("the genuine listener's address");
    // The caller pins the genuine server. The impostor holds a different identity — it is a
    // whole listener of its own, so it answers a hello exactly as a real server does, and
    // signs with the key it has.
    let pinned = HybridVerifyingKey::from_bytes(&genuine.verifying_key_bytes())
        .expect("the genuine verifying key");
    assert_ne!(
        impostor.verifying_key_bytes(),
        genuine.verifying_key_bytes(),
        "the two listeners have to hold different identities, or there is no impostor"
    );

    // Both listeners accept: the impostor must answer for the mismatch to be reachable at
    // all, and the genuine one must be able to accept, so that its accepting nothing is a
    // fact about the walk and not about the harness.
    let impostor_accept = {
        let impostor = impostor.clone();
        tokio::spawn(async move { impostor.accept().await })
    };
    let genuine_accept = {
        let genuine = genuine.clone();
        tokio::spawn(async move { genuine.accept().await })
    };

    let err = connect_udp_trying_each_address(
        "impostor-first",
        &[impostor_addr, genuine_addr],
        CLIENT_HANDSHAKE_DEADLINE,
        {
            let pinned = pinned.clone();
            move |transport| {
                PhantomSession::connect_with_transport("impostor-first", transport, pinned.clone())
            }
        },
    )
    .await
    .expect_err("an address that answered as the wrong identity has to reach the caller");
    assert!(
        matches!(err, CoreError::ServerIdentityMismatch),
        "the caller has to be told an impostor answered, as the typed variant it branches \
         on; got {err:?}"
    );

    // And the walk stopped: the genuine address was never contacted, so the refusal ended
    // the walk rather than merely being remembered while it carried on.
    assert!(
        timeout(QUIET, genuine_accept).await.is_err(),
        "the walk went on to the genuine address after an impostor refused, so the refusal \
         did not end it"
    );
    impostor_accept.abort();
    impostor.shutdown();
    genuine.shutdown();
}
