use crate::api::session::SessionCommand;
use crate::errors::CoreError;
use crate::transport::multiplexer::{StreamHandle, StreamMessage};
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

/// A single multiplexed stream inside an established [`PhantomSession`].
///
/// Created by the session's stream multiplexer (one per logical stream id).
/// Outbound data is queued to the session's data pump over the `tx` command
/// channel (`send_reliable` / `send_unreliable`); inbound demultiplexed data
/// arrives on `rx`. The session owns all encryption and transport — a
/// `PhantomStream` is just the per-stream send/recv handle exposed over FFI.
///
/// [`PhantomSession`]: crate::api::session::PhantomSession
#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct PhantomStream {
    stream_id: u32,
    /// Channel to send data to the session to be packaged and sent
    tx: mpsc::Sender<SessionCommand>,
    /// Receiver for incoming demultiplexed stream data
    rx: Mutex<mpsc::Receiver<StreamMessage>>,
}

impl PhantomStream {
    pub fn new(handle: StreamHandle, tx: mpsc::Sender<SessionCommand>) -> Self {
        Self {
            stream_id: handle.stream_id,
            tx,
            rx: Mutex::new(handle.rx),
        }
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
    /// [`MAX_APP_CHUNK`](crate::transport::mtu::MAX_APP_CHUNK) bytes — one chunk
    /// plus its packet overhead is exactly one PhantomUDP datagram — and buffers
    /// each chunk as its own reliable write, so the peer's [`recv`](Self::recv)
    /// yields one result *per chunk*, not one per `send_reliable`. Order is
    /// guaranteed; grouping is not, and nothing marks where one call's payload
    /// ended.
    ///
    /// Frame the messages yourself if you need them: write a length prefix ahead
    /// of each payload and accumulate `recv` results until the declared length is
    /// complete. `testbed/src/framing.rs` in this repository is a worked example.
    pub async fn send_reliable(&self, data: Vec<u8>) -> Result<(), CoreError> {
        self.tx
            .send(SessionCommand::SendStreamReliable {
                stream_id: self.stream_id,
                data: Bytes::from(data),
            })
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }

    /// Queue `data` for best-effort delivery on this stream — no retransmit, no
    /// ordering guarantee, and no delivery guarantee.
    ///
    /// # ⚠ This is a byte stream, not a message channel
    ///
    /// **Message boundaries are not preserved**, exactly as in
    /// [`send_reliable`](Self::send_reliable): the pump splits `data` into
    /// chunks of [`MAX_APP_CHUNK`](crate::transport::mtu::MAX_APP_CHUNK) bytes
    /// and sends each on its own. Here that is sharper than on the reliable
    /// path, because the chunks are independent datagrams: any subset of them
    /// can be lost or arrive out of order, so a payload larger than one chunk
    /// can reach the peer with a hole in the middle and no signal that it did.
    ///
    /// Keep unreliable payloads within one chunk, or carry your own length
    /// prefix and sequence number and drop incomplete messages —
    /// `testbed/src/framing.rs` in this repository is a worked example of the
    /// framing half.
    pub async fn send_unreliable(&self, data: Vec<u8>) -> Result<(), CoreError> {
        self.tx
            .send(SessionCommand::SendStreamUnreliable {
                stream_id: self.stream_id,
                data: Bytes::from(data),
            })
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }

    /// Receive the next data frame from this stream.
    ///
    /// Returns:
    /// - `Ok(Some(bytes))` — a data payload arrived.
    /// - `Ok(None)` — the peer sent a clean FIN; the stream is half-closed
    ///   for reading. No more data will arrive on this stream.
    /// - `Err(CoreError::ConnectionClosed)` — the underlying session ended
    ///   (the mpsc channel was dropped) before a clean EOF was signalled.
    ///   This indicates an abnormal termination rather than a graceful close.
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
                    // The mpsc sender was dropped without a Close signal, meaning
                    // the session ended abnormally (e.g. network failure, session
                    // close before stream teardown).
                    return Err(CoreError::ConnectionClosed);
                }
            }
        }
    }

    /// Set this stream's scheduler priority (higher = drained first). Takes
    /// effect on the next drain pass.
    pub async fn set_priority(&self, priority: u32) -> Result<(), CoreError> {
        self.tx
            .send(SessionCommand::SetStreamPriority {
                stream_id: self.stream_id,
                priority,
            })
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }

    /// Close this stream; the peer will see EOF on its read half.
    ///
    /// Named `disconnect` rather than `close` for the same reason as
    /// `PhantomSession::disconnect` — UniFFI's Kotlin generator emits
    /// `AutoCloseable.close()` on every object.
    pub async fn disconnect(&self) -> Result<(), CoreError> {
        self.tx
            .send(SessionCommand::CloseStream {
                stream_id: self.stream_id,
            })
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::multiplexer::StreamHandle;
    use tokio::sync::mpsc;

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
        let ps = PhantomStream::new(handle, cmd_tx.clone());
        (ps, stream_msg_tx, cmd_tx)
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
}
