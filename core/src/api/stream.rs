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

    pub async fn send_reliable(&self, data: Vec<u8>) -> Result<(), CoreError> {
        self.tx
            .send(SessionCommand::SendStreamReliable {
                stream_id: self.stream_id,
                data: Bytes::from(data),
            })
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }

    pub async fn send_unreliable(&self, data: Vec<u8>) -> Result<(), CoreError> {
        self.tx
            .send(SessionCommand::SendStreamUnreliable {
                stream_id: self.stream_id,
                data: Bytes::from(data),
            })
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }

    pub async fn recv(&self) -> Result<Vec<u8>, CoreError> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Some(StreamMessage::Data(b)) => return Ok(b.to_vec()),
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
                    return Err(CoreError::NetworkError("Stream closed by peer".into()));
                }
                None => {
                    return Err(CoreError::NetworkError("Stream closed locally".into()));
                }
            }
        }
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
