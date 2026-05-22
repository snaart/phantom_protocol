use crate::api::session::SessionCommand;
use crate::errors::CoreError;
use crate::transport::multiplexer::{StreamHandle, StreamMessage};
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

#[derive(uniffi::Object)]
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

#[uniffi::export(async_runtime = "tokio")]
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
                    // Just log for now until ARQ is implemented
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

    pub async fn close(&self) -> Result<(), CoreError> {
        self.tx
            .send(SessionCommand::CloseStream {
                stream_id: self.stream_id,
            })
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }
}
