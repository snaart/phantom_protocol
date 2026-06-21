//! Stream Demultiplexer
//!
//! Routes decrypted inbound payloads to their target streams based on the
//! `stream_id` carried in the `PhantomPacket` header. A lightweight, zero-copy
//! routing table (`DashMap<stream_id, mpsc::Sender>`) keyed by `u32` stream id:
//! the recv pump looks up the sender and hands off the `Bytes` payload without
//! copying. Stream id 0 is reserved for the session-level control channel;
//! unknown stream ids are dropped with a log warning.

use crate::transport::types::SequenceNumber;
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::mpsc;

/// Messages routed to a stream by the demultiplexer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamMessage {
    /// Normal data payload
    Data(Bytes),
    /// Acknowledgment of a specific sequence number
    Ack(SequenceNumber),
    /// Stream closure signal
    Close,
}

/// A lightweight stream demultiplexer that routes packets to registered streams.
///
/// # Design
///
/// ```text
///   UDP Socket → StreamDemultiplexer → Stream[0] (reliable)
///                                    → Stream[1] (reliable)
///                                    → Stream[2] (unreliable)
///                                    → control channel
/// ```
///
/// Each stream is identified by a `u32` stream ID extracted from the packet header.
/// Unrecognized stream IDs are dropped (with a log warning).
pub struct StreamDemultiplexer {
    /// Active stream senders: stream_id → sender channel
    streams: DashMap<u32, mpsc::Sender<StreamMessage>>,
    /// Control channel for session-level messages (stream_id = 0)
    control_tx: mpsc::Sender<Bytes>,
    /// Next stream ID to allocate
    next_stream_id: AtomicU32,
}

/// Handle returned when a stream is registered with the demultiplexer.
pub struct StreamHandle {
    /// The stream ID assigned to this stream
    pub stream_id: u32,
    /// Receiver end for incoming packets
    pub rx: mpsc::Receiver<StreamMessage>,
}

impl StreamDemultiplexer {
    /// Create a new demultiplexer with a control channel.
    ///
    /// The control channel (stream_id = 0) receives session-level packets
    /// such as keepalives, migration signals, and stream management.
    pub fn new(control_buffer: usize) -> (Self, mpsc::Receiver<Bytes>) {
        let (control_tx, control_rx) = mpsc::channel(control_buffer);
        let mux = Self {
            streams: DashMap::new(),
            control_tx,
            next_stream_id: AtomicU32::new(2), // 0 = control, 1 = raw-app session channel
        };
        (mux, control_rx)
    }

    /// Register a new stream and get back a handle with the assigned ID.
    ///
    /// `buffer_size` controls the depth of the per-stream receive buffer.
    pub fn open_stream(&self, buffer_size: usize) -> StreamHandle {
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(buffer_size);
        self.streams.insert(stream_id, tx);
        StreamHandle { stream_id, rx }
    }

    /// Register a stream with a specific ID (e.g., for accepting remote-initiated streams).
    pub fn register_stream(&self, stream_id: u32, buffer_size: usize) -> StreamHandle {
        let (tx, rx) = mpsc::channel(buffer_size);
        self.streams.insert(stream_id, tx);
        // Update next_stream_id if necessary to avoid collisions
        let _ = self
            .next_stream_id
            .fetch_max(stream_id + 1, Ordering::Relaxed);
        StreamHandle { stream_id, rx }
    }

    /// Remove a stream from the routing table.
    pub fn close_stream(&self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    /// Route data payload to the appropriate stream.
    ///
    /// Returns `true` if the packet was successfully delivered,
    /// `false` if the stream was not found or the buffer was full.
    pub fn route_data(&self, stream_id: u32, payload: Bytes) -> bool {
        if stream_id == 0 {
            // Control channel
            return self.control_tx.try_send(payload).is_ok();
        }

        if let Some(sender) = self.streams.get(&stream_id) {
            sender.try_send(StreamMessage::Data(payload)).is_ok()
        } else {
            log::warn!(
                "StreamDemultiplexer: dropping data for unknown stream_id={}",
                stream_id
            );
            false
        }
    }

    /// Route data asynchronously (waits if buffer is full).
    pub async fn route_data_async(&self, stream_id: u32, payload: Bytes) -> bool {
        if stream_id == 0 {
            return self.control_tx.send(payload).await.is_ok();
        }

        if let Some(sender) = self.streams.get(&stream_id) {
            sender.send(StreamMessage::Data(payload)).await.is_ok()
        } else {
            log::warn!(
                "StreamDemultiplexer: dropping data for unknown stream_id={}",
                stream_id
            );
            false
        }
    }

    /// Route an ACK signal to a stream **without blocking**. Returns
    /// `false` if the stream is unknown or its buffer is full — the recv pump
    /// uses this on its never-block path, where a vestigial/absent stream
    /// consumer must not stall inbound ACK/control processing.
    pub fn route_ack(&self, stream_id: u32, seq: SequenceNumber) -> bool {
        if stream_id == 0 {
            return false;
        }
        if let Some(sender) = self.streams.get(&stream_id) {
            sender.try_send(StreamMessage::Ack(seq)).is_ok()
        } else {
            false
        }
    }

    /// Route a stream-closure signal **without blocking** (see [`Self::route_ack`]).
    pub fn route_close(&self, stream_id: u32) -> bool {
        if stream_id == 0 {
            return false;
        }
        if let Some(sender) = self.streams.get(&stream_id) {
            sender.try_send(StreamMessage::Close).is_ok()
        } else {
            false
        }
    }

    /// Route an ACK signal to a stream asynchronously.
    pub async fn route_ack_async(&self, stream_id: u32, seq: SequenceNumber) -> bool {
        if stream_id == 0 {
            return false;
        }

        if let Some(sender) = self.streams.get(&stream_id) {
            sender.send(StreamMessage::Ack(seq)).await.is_ok()
        } else {
            log::warn!(
                "StreamDemultiplexer: dropping ACK for unknown stream_id={}",
                stream_id
            );
            false
        }
    }

    /// Route a stream closure signal asynchronously.
    pub async fn route_close_async(&self, stream_id: u32) -> bool {
        if stream_id == 0 {
            return false;
        }

        if let Some(sender) = self.streams.get(&stream_id) {
            sender.send(StreamMessage::Close).await.is_ok()
        } else {
            log::warn!(
                "StreamDemultiplexer: dropping CLOSE for unknown stream_id={}",
                stream_id
            );
            false
        }
    }

    /// Number of active streams (excluding control channel).
    pub fn active_stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Check if a stream is registered.
    pub fn has_stream(&self, stream_id: u32) -> bool {
        self.streams.contains_key(&stream_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_demux_open_and_route() {
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);

        let handle = demux.open_stream(16);
        let sid = handle.stream_id;
        let mut rx = handle.rx;

        assert!(demux.has_stream(sid));
        assert_eq!(demux.active_stream_count(), 1);

        // Route a packet
        let data = Bytes::from_static(b"hello stream");
        assert!(demux.route_data(sid, data.clone()));

        // Receive it
        let received = rx.recv().await.unwrap();
        assert_eq!(received, StreamMessage::Data(data));
    }

    #[tokio::test]
    async fn test_demux_control_channel() {
        let (demux, mut ctrl_rx) = StreamDemultiplexer::new(16);

        let data = Bytes::from_static(b"control msg");
        assert!(demux.route_data(0, data.clone()));

        let received = ctrl_rx.recv().await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn test_demux_unknown_stream() {
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);

        // Route to non-existent stream
        let data = Bytes::from_static(b"lost");
        assert!(!demux.route_data(999, data));
    }

    #[tokio::test]
    async fn test_demux_close_stream() {
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);

        let handle = demux.open_stream(16);
        let sid = handle.stream_id;
        assert!(demux.has_stream(sid));

        demux.close_stream(sid);
        assert!(!demux.has_stream(sid));
        assert_eq!(demux.active_stream_count(), 0);
    }

    #[tokio::test]
    async fn test_demux_multiple_streams() {
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);

        let h1 = demux.open_stream(16);
        let h2 = demux.open_stream(16);
        let h3 = demux.open_stream(16);

        assert_ne!(h1.stream_id, h2.stream_id);
        assert_ne!(h2.stream_id, h3.stream_id);
        assert_eq!(demux.active_stream_count(), 3);
    }
}
