use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::api::session::{ConnectionState, ControlCommand, SessionCommand, StreamLink};
use crate::errors::CoreError;
use crate::transport::multiplexer::{StreamHandle, StreamMessage};

/// A single multiplexed stream inside an established [`PhantomSession`].
///
/// Created by the session's stream multiplexer (one per logical stream id).
/// Outbound data is queued to the session's data pump (`send_reliable` /
/// `send_unreliable`); inbound demultiplexed data arrives on `recv`. The session
/// owns all encryption and transport — a `PhantomStream` is just the per-stream
/// send/recv handle exposed over FFI.
///
/// # Letting go of a stream
///
/// Dropping the last reference to this handle — letting it go out of scope, or
/// releasing it in a garbage-collected binding — closes the stream's writing half
/// exactly as [`disconnect`](Self::disconnect) would, **after** every write already
/// made on the handle: nothing the handle sent is lost to the drop, and the peer reads
/// those bytes and then its EOF. A stream this side opened and never wrote a reliable
/// byte on has not reached the peer at all, and simply goes.
///
/// Once this side's close is acknowledged the session forgets the stream, whether or
/// not the peer has closed its own half — nobody is left here to read what that half
/// carries. Anything the peer sends on it afterwards is acknowledged and discarded, and
/// the session keeps granting the peer flow-control room on it, so the peer's writes
/// complete however much it goes on writing, and its other streams are not held up
/// behind this one. Nothing tells the peer its bytes went unread; if that matters, say
/// so at the application level before letting go. To read the peer's side to its end,
/// keep the handle until
/// [`recv`](Self::recv) returns `Ok(None)`: a held handle keeps its stream for as long
/// as the peer's half is open.
///
/// [`PhantomSession`]: crate::api::session::PhantomSession
#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct PhantomStream {
    stream_id: u32,
    /// The channels to the session's data pump: writes and the close, control that
    /// writes nothing, and the report this handle makes when it is dropped.
    link: StreamLink,
    /// Receiver for incoming demultiplexed stream data
    rx: Mutex<mpsc::Receiver<StreamMessage>>,
    /// The owning session's published [`ConnectionState`], shared with the session
    /// handle and written by its data pump.
    ///
    /// A stream's writes go down the same command channel as the session's and are
    /// refused by the same pump for the same reason, so they have to be able to ask
    /// the same question before returning `Ok` to a caller. Without it a
    /// `send_reliable` during the peer's draining window reports success for bytes
    /// that never reach the wire — the session-level defect, one layer down.
    session_state: Arc<AtomicU8>,
    /// Whether anything has ever been put on this handle's command channel — a write, or
    /// its close.
    ///
    /// Read by `Drop` to tell a stream that has been used from one that has not. A handle
    /// that queued nothing has nothing waiting in that channel for its stream's close to
    /// stay ordered behind, which is what lets an unused stream be retired on the spot
    /// instead of through the pump (see
    /// [`StreamRegistry`](crate::api::session::StreamRegistry)). Set before the send rather
    /// than after it, so a `send` abandoned mid-`await` still counts as having used the
    /// handle: erring towards "used" costs a trip through the pump and nothing else, while
    /// erring the other way would be a queued write whose stream had already gone.
    issued_command: AtomicBool,
}

impl PhantomStream {
    pub(crate) fn new(
        handle: StreamHandle,
        link: StreamLink,
        session_state: Arc<AtomicU8>,
    ) -> Self {
        Self {
            stream_id: handle.stream_id,
            link,
            rx: Mutex::new(handle.rx),
            session_state,
            issued_command: AtomicBool::new(false),
        }
    }

    /// The owning session's current state.
    fn session_state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.session_state.load(Ordering::Relaxed))
    }

    /// Refuse an outbound command the pump would discard.
    ///
    /// Only [`ConnectionState::Draining`] is refused here. Every other state either
    /// still carries writes or already fails at the channel — a torn-down pump drops
    /// the receiver, so `tx.send` errors on its own. Draining is the one state in
    /// which the channel is alive, the command is accepted by it, and the pump then
    /// throws the payload away.
    fn refuse_while_draining(&self) -> Result<(), CoreError> {
        if self.session_state() == ConnectionState::Draining {
            return Err(CoreError::ConnectionClosed);
        }
        Ok(())
    }
}

#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
impl PhantomStream {
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Queue `data` for reliable, in-order delivery on this stream.
    ///
    /// # ⚠ This is a byte stream, not a message channel
    ///
    /// **Message boundaries are not preserved.** The session's data pump splits
    /// `data` into chunks of
    /// [`MAX_APP_CHUNK`](crate::transport::mtu::MAX_APP_CHUNK) bytes — 1156 on
    /// this build, sized so that one chunk plus its packet overhead is exactly
    /// one PhantomUDP datagram — and buffers each chunk as its own reliable
    /// write, so the peer's [`recv`](Self::recv) yields one result *per chunk*,
    /// not one per `send_reliable`. Order is guaranteed; grouping is not, and
    /// nothing marks where one call's payload ended.
    ///
    /// Frame the messages yourself if you need them: write a length prefix ahead
    /// of each payload and accumulate `recv` results until the declared length is
    /// complete. `testbed/src/framing.rs` in this repository is a worked example.
    ///
    /// Returns [`CoreError::ConnectionClosed`] once the owning session is
    /// [`Draining`](crate::api::session::ConnectionState::Draining) the peer's close,
    /// without queueing anything: the peer's session is over, so this call cannot put
    /// `data` on the wire.
    pub async fn send_reliable(&self, data: Vec<u8>) -> Result<(), CoreError> {
        self.refuse_while_draining()?;
        self.issued_command.store(true, Ordering::Relaxed);
        self.link
            .commands
            .send(SessionCommand::SendStreamReliable {
                stream_id: self.stream_id,
                data: Bytes::from(data),
            })
            .await
            .map_err(|_| CoreError::ConnectionClosed)
    }

    /// Queue `data` for best-effort delivery on this stream — no retransmit, no
    /// ordering guarantee, and no delivery guarantee.
    ///
    /// # ⚠ This is a byte stream, not a message channel
    ///
    /// **Message boundaries are not preserved**, exactly as in
    /// [`send_reliable`](Self::send_reliable): the pump splits `data` into
    /// chunks of [`MAX_APP_CHUNK`](crate::transport::mtu::MAX_APP_CHUNK) bytes
    /// — 1156 on this build — and sends each on its own. Here that is sharper
    /// than on the reliable path, because the chunks are independent datagrams:
    /// any subset of them can be lost or arrive out of order, so a payload
    /// larger than one chunk can reach the peer with a hole in the middle and no
    /// signal that it did.
    ///
    /// Keep unreliable payloads within one chunk, or carry your own length
    /// prefix and sequence number and drop incomplete messages —
    /// `testbed/src/framing.rs` in this repository is a worked example of the
    /// framing half.
    ///
    /// Returns [`CoreError::ConnectionClosed`] once the owning session is
    /// [`Draining`](crate::api::session::ConnectionState::Draining) the peer's close,
    /// for the same reason as [`send_reliable`](Self::send_reliable).
    pub async fn send_unreliable(&self, data: Vec<u8>) -> Result<(), CoreError> {
        self.refuse_while_draining()?;
        self.issued_command.store(true, Ordering::Relaxed);
        self.link
            .commands
            .send(SessionCommand::SendStreamUnreliable {
                stream_id: self.stream_id,
                data: Bytes::from(data),
            })
            .await
            .map_err(|_| CoreError::ConnectionClosed)
    }

    /// Receive the next data frame from this stream.
    ///
    /// Returns:
    /// - `Ok(Some(bytes))` — a data payload arrived.
    /// - `Ok(None)` — the peer sent a clean FIN; the stream is half-closed
    ///   for reading. No more data will arrive on this stream. Exactly once: a further
    ///   call on a stream whose FIN has already been reported gets the `Err` below.
    /// - `Err(CoreError::ConnectionClosed)` — the session ended before a FIN arrived on
    ///   this stream.
    ///
    /// **The session ending is an `Err` here, not `Ok(None)`, even when it ended in the
    /// orderly way.** `Ok(None)` is a statement about *this stream*: the peer closed its
    /// writing half, so everything it meant to send has been read. The end of the session
    /// says nothing of the kind — the peer may have been half-way through writing on this
    /// stream — so reporting it as a clean end of stream would tell the caller it had
    /// everything when the truth is that nobody can now say. The distinction survives in
    /// both directions: a stream whose FIN did arrive reports `Ok(None)` first and the
    /// error only afterwards, so a reader that reads to EOF never sees the error at all.
    ///
    /// Either way the call resolves. Whatever was already delivered into this stream is
    /// handed over first, in order, and the end is reported after it.
    pub async fn recv(&self) -> Result<Option<Vec<u8>>, CoreError> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Some(StreamMessage::Data(b)) => return Ok(Some(b.to_vec())),
                Some(StreamMessage::Ack(seq)) => {
                    log::debug!(
                        "PhantomStream {}: received ACK for seq {}",
                        self.stream_id,
                        seq
                    );
                    // This `recv()` surfaces only application data to the caller.
                    // Reliable delivery / retransmission (the L1 RTO + SACK
                    // fast-retransmit path) lives in the data pump and the
                    // reliable-stream layer (`transport/stream.rs`), not here, so
                    // a stream-level ACK is informational at this surface: log it
                    // and keep waiting for the next data frame.
                    continue;
                }
                Some(StreamMessage::Close) => {
                    // Peer sent a clean FIN — EOF, not an error.
                    return Ok(None);
                }
                None => {
                    // Every sender for this stream is gone: its route was dropped, which
                    // happens when the stream is retired and when the session ends. Either
                    // way no FIN arrived on this stream, so what can be said is that it is
                    // over and not that it was read to its end — see this method's
                    // documentation for why that is an error and not `Ok(None)`.
                    return Err(CoreError::ConnectionClosed);
                }
            }
        }
    }

    /// Set this stream's scheduler priority (higher = drained first). Takes
    /// effect on the next drain pass.
    ///
    /// The request does not wait behind writes queued on the session, so it
    /// applies to whatever the stream holds at that pass — writes made before
    /// this call included, even if they are still waiting for room.
    ///
    /// Returns [`CoreError::ConnectionClosed`] when the session is over, which is the same
    /// answer [`send_reliable`](Self::send_reliable), [`send_unreliable`](Self::send_unreliable)
    /// and [`disconnect`](Self::disconnect) give. It used to be a
    /// `NetworkError("Session closed")` here alone, so three of this type's four outbound
    /// calls reported an ended session as a typed close and the fourth reported it as a
    /// network fault — which is worse for a caller matching on the error than either answer
    /// consistently would be: the one arm that has to be written as a string comparison is
    /// the one nobody writes, and a session that ended in the orderly way was reported as a
    /// failure.
    ///
    /// Unlike the three of them it is not refused while the session is
    /// [`Draining`](crate::api::session::ConnectionState::Draining). Those carry a payload
    /// the pump would throw away, and returning `Ok` for bytes that never reach the wire is
    /// the defect that refusal exists to stop; a priority is not a payload — it is applied
    /// to the stream's own scheduling for as long as the stream still has one, and asks
    /// nothing of the peer.
    pub async fn set_priority(&self, priority: u32) -> Result<(), CoreError> {
        self.link
            .control
            .send(ControlCommand::SetStreamPriority {
                stream_id: self.stream_id,
                priority,
            })
            .await
            .map_err(|_| CoreError::ConnectionClosed)
    }

    /// Close this side of the stream; the peer will see EOF on its read half,
    /// after everything written on this handle before the call.
    ///
    /// Only the writing half closes. [`recv`](Self::recv) on this handle keeps
    /// returning what the peer sends until the peer closes its half as well, and the
    /// session holds the stream — counting it against its limit on concurrent
    /// streams — until both halves are closed, or until this close is acknowledged
    /// and the handle has been let go of (see the type's documentation).
    ///
    /// A write made on this handle after this call, reliable or unreliable, is never
    /// sent. The call still returns `Ok` — the session takes the command in as it
    /// takes any other — and the pump discards it when it reaches it. It reaches it
    /// only once this close has taken its place in the stream, which may be some time
    /// if the stream's send buffer is full, so the write cannot reach the wire ahead
    /// of the close either: the peer is told the stream ended, and nothing follows.
    ///
    /// Named `disconnect` rather than `close` for the same reason as
    /// `PhantomSession::disconnect` — UniFFI's Kotlin generator emits
    /// `AutoCloseable.close()` on every object.
    ///
    /// The FIN is a reliable write like any other, so this returns
    /// [`CoreError::ConnectionClosed`] once the owning session is
    /// [`Draining`](crate::api::session::ConnectionState::Draining): the peer would
    /// never see the EOF, and the stream is about to end with the session anyway.
    pub async fn disconnect(&self) -> Result<(), CoreError> {
        self.refuse_while_draining()?;
        self.issued_command.store(true, Ordering::Relaxed);
        self.link
            .commands
            .send(SessionCommand::CloseStream {
                stream_id: self.stream_id,
            })
            .await
            .map_err(|_| CoreError::ConnectionClosed)
    }
}

/// Tell the session's pump that nobody holds this stream any more.
///
/// The report travels on a channel of its own, because `Drop` can neither wait for room in
/// the command channel nor fail usefully. The pump acts on it only once it has taken in
/// every write this handle queued before it went — see the type's documentation for what
/// it does then. A session that has already ended has no pump to tell, and the send fails
/// harmlessly.
///
/// **A stream nothing was ever written on does not go that way.** It has no close to send,
/// no writes to stay ordered behind and nobody left to read it, and the peer has never
/// heard of it, so the pump would have nothing to do but take it out of two tables — which
/// this does here instead, at the cost of two map removals. The difference is not a
/// micro-optimisation: reporting it costs the pump a wake-up, and a wake-up costs its send
/// loop a pass over every stream the session holds, so opening and dropping handles used to
/// cost time quadratic in how many were dropped, and held up the peer's own streams while
/// the backlog cleared.
impl Drop for PhantomStream {
    fn drop(&mut self) {
        if !self.issued_command.load(Ordering::Relaxed)
            && self.link.registry.retire_untouched_local(self.stream_id)
        {
            return;
        }
        let _ = self.link.released.send(self.stream_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::multiplexer::StreamHandle;
    use tokio::sync::mpsc;

    /// A link whose writes go to `commands` and whose other channels lead nowhere.
    fn link_to(commands: mpsc::Sender<SessionCommand>) -> StreamLink {
        let (control, _) = mpsc::channel(1);
        let (released, _) = mpsc::unbounded_channel();
        StreamLink {
            commands,
            control,
            released,
            registry: crate::api::session::detached_stream_registry(),
        }
    }

    /// Build a minimal PhantomStream with a test-controlled channel.
    fn make_stream(
        stream_id: u32,
        buffer: usize,
    ) -> (
        PhantomStream,
        mpsc::Sender<StreamMessage>,
        mpsc::Sender<SessionCommand>,
    ) {
        let (stream_msg_tx, stream_msg_rx) = mpsc::channel::<StreamMessage>(buffer);
        let (cmd_tx, _cmd_rx) = mpsc::channel::<SessionCommand>(16);
        let handle = StreamHandle {
            stream_id,
            rx: stream_msg_rx,
        };
        let ps = PhantomStream::new(
            handle,
            link_to(cmd_tx.clone()),
            Arc::new(AtomicU8::new(ConnectionState::Connected as u8)),
        );
        (ps, stream_msg_tx, cmd_tx)
    }

    /// Every outbound call on a stream whose session is draining its peer's close is
    /// refused, and refused without putting anything in the command channel.
    ///
    /// The channel is the point. It is alive and has room — the pump is still running,
    /// still reading commands, and still needs to so that a `Close` can land — so a
    /// write offered here is *accepted* by the channel and *discarded* by the pump,
    /// which is a success return for bytes that never reach the wire. Asserting the
    /// channel is still empty afterwards is what distinguishes a genuine refusal from
    /// an error that happens to be returned by a queue that took the payload anyway.
    ///
    /// `recv()` is deliberately not refused and is checked here so that stays true: a
    /// draining session is still reading, and the data behind the peer's close is the
    /// whole reason the window exists.
    #[tokio::test]
    async fn a_draining_session_refuses_every_stream_write_without_queueing_it() {
        let (stream_msg_tx, stream_msg_rx) = mpsc::channel::<StreamMessage>(8);
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<SessionCommand>(16);
        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        let handle = StreamHandle {
            stream_id: 3,
            rx: stream_msg_rx,
        };
        let ps = PhantomStream::new(handle, link_to(cmd_tx), state.clone());

        ps.send_reliable(b"connected".to_vec())
            .await
            .expect("a connected session accepts a stream write");
        assert!(
            cmd_rx.try_recv().is_ok(),
            "the healthy case has to reach the channel, or the assertions below are \
             satisfied by a stream that never worked"
        );

        state.store(ConnectionState::Draining as u8, Ordering::Relaxed);

        assert!(matches!(
            ps.send_reliable(b"draining".to_vec()).await,
            Err(CoreError::ConnectionClosed)
        ));
        assert!(matches!(
            ps.send_unreliable(b"draining".to_vec()).await,
            Err(CoreError::ConnectionClosed)
        ));
        assert!(matches!(
            ps.disconnect().await,
            Err(CoreError::ConnectionClosed)
        ));
        assert!(
            cmd_rx.try_recv().is_err(),
            "a refused write must not be sitting in the command channel — an error \
             returned over a payload that was queued anyway is still a payload the \
             pump will discard"
        );

        stream_msg_tx
            .send(StreamMessage::Data(Bytes::from_static(b"behind-the-close")))
            .await
            .expect("the delivery channel is untouched");
        assert_eq!(
            ps.recv().await.expect("draining still reads"),
            Some(b"behind-the-close".to_vec()),
            "a draining session must keep delivering what was in flight behind the \
             close; refusing reads too would restore the loss the window removed"
        );
    }

    /// `recv()` returns `Ok(Some(bytes))` for a Data message.
    #[tokio::test]
    async fn recv_returns_some_data() {
        let (ps, tx, _cmd) = make_stream(3, 8);
        tx.send(StreamMessage::Data(Bytes::from_static(b"hello")))
            .await
            .unwrap();
        let result = ps.recv().await.unwrap();
        assert_eq!(result, Some(b"hello".to_vec()));
    }

    /// `recv()` returns `Ok(None)` on a clean `StreamMessage::Close`.
    #[tokio::test]
    async fn recv_returns_none_on_clean_close() {
        let (ps, tx, _cmd) = make_stream(3, 8);
        tx.send(StreamMessage::Close).await.unwrap();
        let result = ps.recv().await;
        assert!(
            matches!(result, Ok(None)),
            "clean FIN must return Ok(None), got {:?}",
            result
        );
    }

    /// `recv()` returns `Err(ConnectionClosed)` when the sender is dropped
    /// without sending a Close signal.
    #[tokio::test]
    async fn recv_returns_connection_closed_on_channel_drop() {
        let (ps, tx, _cmd) = make_stream(3, 8);
        drop(tx); // abnormal: session gone, no FIN sent
        let result = ps.recv().await;
        assert!(
            matches!(result, Err(CoreError::ConnectionClosed)),
            "channel drop must return Err(ConnectionClosed), got {:?}",
            result
        );
    }

    /// `StreamMessage::Ack` messages are skipped transparently.
    /// After one Ack and then a Data frame, `recv()` returns the data.
    #[tokio::test]
    async fn recv_skips_ack_messages() {
        let (ps, tx, _cmd) = make_stream(3, 8);
        tx.send(StreamMessage::Ack(42)).await.unwrap();
        tx.send(StreamMessage::Data(Bytes::from_static(b"after ack")))
            .await
            .unwrap();
        let result = ps.recv().await.unwrap();
        assert_eq!(result, Some(b"after ack".to_vec()));
    }

    /// Data followed by Close — first call returns data, second returns None.
    #[tokio::test]
    async fn recv_data_then_clean_close_in_sequence() {
        let (ps, tx, _cmd) = make_stream(3, 8);
        tx.send(StreamMessage::Data(Bytes::from_static(b"payload")))
            .await
            .unwrap();
        tx.send(StreamMessage::Close).await.unwrap();
        let first = ps.recv().await.unwrap();
        assert_eq!(first, Some(b"payload".to_vec()));
        let second = ps.recv().await;
        assert!(
            matches!(second, Ok(None)),
            "second recv after Close must return Ok(None), got {:?}",
            second
        );
    }
    /// Every outbound call on a stream reports an ended session the same way, as
    /// [`CoreError::ConnectionClosed`].
    ///
    /// **The defect.** `send_reliable`, `send_unreliable` and `disconnect` were retyped to
    /// the typed close and `set_priority` was left behind, still answering
    /// `NetworkError("Session closed")`.
    ///
    /// **What a consumer sees.** Three of this type's four outbound calls report an ended
    /// session as a typed close and the fourth reports it as a network fault. A caller
    /// matching on the error either misses the fourth — a `match` arm nobody writes, because
    /// writing it means comparing a string — or has to handle both shapes for one event; and
    /// a session that ended in the orderly way is described as something going wrong. Three
    /// of four is worse for them than either answer applied consistently.
    ///
    /// **Why it comes back unnoticed.** Nothing fails: the call still returns `Err`, the
    /// stream is still gone, and the difference is only in what the error *is*. It is also
    /// the one of the four with no payload, so it has no test of its own about where its
    /// bytes went, and it was retyped by a change whose subject was the other three. Driven
    /// by dropping the receiving half of each channel, which is what a torn-down pump leaves
    /// behind.
    #[tokio::test]
    async fn every_outbound_call_reports_an_ended_session_as_a_typed_close() {
        let (stream_msg_tx, stream_msg_rx) = mpsc::channel::<StreamMessage>(8);
        let (cmd_tx, cmd_rx) = mpsc::channel::<SessionCommand>(16);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (released, _released_rx) = mpsc::unbounded_channel();
        let handle = StreamHandle {
            stream_id: 3,
            rx: stream_msg_rx,
        };
        let ps = PhantomStream::new(
            handle,
            StreamLink {
                commands: cmd_tx,
                control: control_tx,
                released,
                registry: crate::api::session::detached_stream_registry(),
            },
            Arc::new(AtomicU8::new(ConnectionState::Connected as u8)),
        );

        // The healthy case first, or the assertions below are satisfied by channels that
        // never worked.
        ps.set_priority(7).await.expect("a live session takes it");
        ps.send_reliable(b"live".to_vec())
            .await
            .expect("a live session takes it");

        // What a pump that has exited leaves behind: nobody holding the receiving end.
        drop(cmd_rx);
        drop(control_rx);
        drop(stream_msg_tx);

        for (what, answer) in [
            ("set_priority", ps.set_priority(1).await),
            ("send_reliable", ps.send_reliable(b"gone".to_vec()).await),
            (
                "send_unreliable",
                ps.send_unreliable(b"gone".to_vec()).await,
            ),
            ("disconnect", ps.disconnect().await),
        ] {
            assert!(
                matches!(answer, Err(CoreError::ConnectionClosed)),
                "{what}() on an ended session must answer the typed close every one of its \
                 siblings answers; got {answer:?}"
            );
        }
        // And the read half agrees, so all five of the type's calls name the same event the
        // same way.
        assert!(matches!(ps.recv().await, Err(CoreError::ConnectionClosed)));
    }

    /// A `PhantomStream` can still be moved across a
    /// [`catch_unwind`](std::panic::catch_unwind) boundary without an
    /// `AssertUnwindSafe` wrapper.
    ///
    /// **The defect.** The stream handle gained a `StreamRegistry`, which holds
    /// `Arc<DashMap<..>>`, and `DashMap` is `!RefUnwindSafe` — so `PhantomStream` silently
    /// stopped implementing `UnwindSafe`. `cargo semver-checks --release-type patch` reports
    /// that as a major-level break, which it is: nothing about the type became fragile, but
    /// an auto trait stopped being derived.
    ///
    /// **What a consumer sees.** Code that compiled at 0.3.0 —
    /// `catch_unwind(move || { let _ = stream; })`, or any generic function with an
    /// `UnwindSafe` bound — stops compiling on a patch upgrade, and the fix at their end is
    /// an `AssertUnwindSafe` they have to reason about.
    ///
    /// **Why it comes back unnoticed.** An auto trait is not written down anywhere, so
    /// nothing in this crate mentions it and no amount of reading the diff shows it going
    /// away; it is implied by every field, and one field of one private struct is enough to
    /// remove it. `cargo semver-checks` catches it, and does not run in `ci.yml` at all — it
    /// runs in `release.yml` under `continue-on-error: true`. This is the check that fails in
    /// the suite that is a required context.
    #[test]
    fn a_phantom_stream_can_cross_a_catch_unwind_boundary() {
        fn moved_into_catch_unwind<T: std::panic::UnwindSafe>(_: T) {}
        let (ps, _tx, _cmd) = make_stream(3, 1);
        moved_into_catch_unwind(ps);
    }
}
