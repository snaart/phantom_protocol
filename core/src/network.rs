use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use crate::errors::CoreError;

/// Protocol Message Types
pub enum ProtocolMessage {
    MlsMessage(Vec<u8>),      // Application, Proposal, Commit
    WelcomeMessage(Vec<u8>),  // Join info
    ExternalCommit(Vec<u8>),  // Client initiated join
}

/// Length-Prefixed Framing Codec
/// Format: [Length: u32 big-endian][Payload: bytes]
pub struct MlsCodec;

const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB Safety Limit

impl Decoder for MlsCodec {
    type Item = ProtocolMessage;
    type Error = CoreError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 1. Check if header is available
        if src.len() < 4 {
            return Ok(None);
        }

        // 2. Read length without advancing (peek)
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length > MAX_MESSAGE_SIZE {
            return Err(CoreError::NetworkError(format!(
                "Message too large: {} bytes", length
            )));
        }

        // 3. Check if full payload is available
        if src.len() < 4 + length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        // 4. Advance and Slice (Zero-Copy)
        src.advance(4);
        let data = src.split_to(length).to_vec();

        // Note: Real protocol would check a type byte here.
        // Defaulting to MlsMessage for this implementation.
        Ok(Some(ProtocolMessage::MlsMessage(data)))
    }
}

impl Encoder<ProtocolMessage> for MlsCodec {
    type Error = CoreError;

    fn encode(&mut self, item: ProtocolMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = match item {
            ProtocolMessage::MlsMessage(d) => d,
            ProtocolMessage::WelcomeMessage(d) => d,
            ProtocolMessage::ExternalCommit(d) => d,
        };

        dst.reserve(4 + data.len());
        dst.put_u32(data.len() as u32);
        dst.put_slice(&data);
        Ok(())
    }
}