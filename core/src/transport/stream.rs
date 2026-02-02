//! Phantom Transport - Stream Management
//!
//! Multiplexed streams within a session.
//! Each stream has independent sequence numbers (no Head-of-Line blocking).

use crate::transport::types::{StreamId, SequenceNumber};

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify, Semaphore};
use bytes::Bytes;

const MAX_PENDING_PACKETS: usize = 1024;

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is open for both directions
    Open,
    /// Local side has finished sending
    HalfClosedLocal,
    /// Remote side has finished sending
    HalfClosedRemote,
    /// Stream is fully closed
    Closed,
}

/// Pending data waiting to be sent
#[derive(Debug)]
struct PendingData {
    sequence: SequenceNumber,
    data: Bytes,
    sent_at: Option<tokio::time::Instant>,
    #[allow(dead_code)]
    retries: u32,
}

/// Stream - multiplexed data channel within a session
pub struct Stream {
    /// Stream identifier
    id: StreamId,
    /// Current state
    state: Mutex<StreamState>,
    /// Send sequence number
    send_sequence: AtomicU32,
    /// Next expected receive sequence
    recv_sequence: AtomicU32,
    /// Send buffer (data waiting to be sent)
    send_buffer: Mutex<VecDeque<PendingData>>,
    /// Unreliable send buffer (fire and forget)
    unreliable_buffer: Mutex<VecDeque<(SequenceNumber, Bytes)>>,
    /// Receive buffer (out-of-order data)
    recv_buffer: Mutex<VecDeque<(SequenceNumber, Bytes)>>,
    /// Ordered receive queue (ready for application)
    recv_ready: Mutex<VecDeque<Bytes>>,
    /// Notify when data is ready to read
    recv_notify: Notify,
    /// Whether stream is finished locally
    local_finished: AtomicBool,
    /// Whether stream is finished remotely
    remote_finished: AtomicBool,
    /// Priority (higher = more important)
    priority: AtomicU32,
    /// Backpressure semaphore
    send_semaphore: Arc<Semaphore>,
}

impl Stream {
    /// Create a new stream
    pub fn new(id: StreamId) -> Self {
        Self {
            id,
            state: Mutex::new(StreamState::Open),
            send_sequence: AtomicU32::new(0),
            recv_sequence: AtomicU32::new(0),
            send_buffer: Mutex::new(VecDeque::new()),
            unreliable_buffer: Mutex::new(VecDeque::new()),
            recv_buffer: Mutex::new(VecDeque::new()),
            recv_ready: Mutex::new(VecDeque::new()),
            recv_notify: Notify::new(),
            local_finished: AtomicBool::new(false),
            remote_finished: AtomicBool::new(false),
            priority: AtomicU32::new(0),
            send_semaphore: Arc::new(Semaphore::new(MAX_PENDING_PACKETS)),
        }
    }

    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Get current state
    pub async fn state(&self) -> StreamState {
        *self.state.lock().await
    }

    /// Get priority
    pub fn priority(&self) -> u32 {
        self.priority.load(Ordering::Relaxed)
    }

    /// Set priority
    pub fn set_priority(&self, priority: u32) {
        self.priority.store(priority, Ordering::Relaxed);
    }

    /// Queue data for sending with reliability
    /// 
    /// Returns the sequence number assigned to this chunk.
    pub async fn send_reliable(&self, data: Bytes) -> SequenceNumber {
        // Backpressure: wait until there is space in the buffer
        let permit = self.send_semaphore.acquire().await.expect("Semaphore closed");
        permit.forget();
        
        let seq = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        
        let pending = PendingData {
            sequence: seq,
            data,
            sent_at: None,
            retries: 0,
        };
        
        self.send_buffer.lock().await.push_back(pending);
        
        seq
    }

    /// Queue data for unreliable sending
    /// 
    /// Returns the sequence number assigned to this chunk.
    pub async fn send_unreliable(&self, data: Bytes) -> SequenceNumber {
        // Unreliable data does not consume buffer permits
        let seq = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        
        self.unreliable_buffer.lock().await.push_back((seq, data));
        
        seq
    }

    /// Get next data chunk to send
    /// Returns: (SequenceNumber, Bytes, is_reliable)
    pub async fn poll_send(&self) -> Option<(SequenceNumber, Bytes, bool)> {
        // First check unreliable buffer (fire and forget)
        if let Some((seq, data)) = self.unreliable_buffer.lock().await.pop_front() {
            return Some((seq, data, false));
        }

        let mut buffer = self.send_buffer.lock().await;
        let now = tokio::time::Instant::now();
        let timeout = std::time::Duration::from_millis(500);
        
        // Find reliable data not yet sent or needing retransmission
        for pending in buffer.iter_mut() {
            if pending.sent_at.is_none() {
                pending.sent_at = Some(now);
                return Some((pending.sequence, pending.data.clone(), true));
            } else if let Some(sent_at) = pending.sent_at {
                if now.duration_since(sent_at) >= timeout {
                    pending.sent_at = Some(now);
                    pending.retries += 1;
                    return Some((pending.sequence, pending.data.clone(), true));
                }
            }
        }
        
        None
    }

    /// Mark a sequence number as acknowledged.
    /// Returns the timestamp when the packet was originally sent and its size, if found.
    pub async fn ack(&self, sequence: SequenceNumber) -> Option<(tokio::time::Instant, u64)> {
        let mut buffer = self.send_buffer.lock().await;
        let mut result = None;
        
        // Find the packet and get its sent_at time
        if let Some(pos) = buffer.iter().position(|p| p.sequence == sequence) {
            let pending = &buffer[pos];
            if let Some(sent_at) = pending.sent_at {
                result = Some((sent_at, pending.data.len() as u64));
            }
            buffer.remove(pos);
            
            // Released space, add permit back
            self.send_semaphore.add_permits(1);
        }
        
        result
    }

    /// Handle received data
    /// 
    /// Data is buffered until it can be delivered in order.
    pub async fn on_receive(&self, sequence: SequenceNumber, data: Bytes) {
        let expected = self.recv_sequence.load(Ordering::SeqCst);
        
        if sequence == expected {
            // In-order delivery
            self.recv_ready.lock().await.push_back(data);
            self.recv_sequence.fetch_add(1, Ordering::SeqCst);
            
            // Try to deliver buffered out-of-order data
            self.deliver_buffered().await;
            
            // Notify waiters
            self.recv_notify.notify_waiters();
        } else if sequence > expected {
            // Out-of-order, buffer it
            self.recv_buffer.lock().await.push_back((sequence, data));
        }
        // sequence < expected means duplicate, ignore it
    }

    /// Try to deliver buffered out-of-order data
    async fn deliver_buffered(&self) {
        let mut recv_buf = self.recv_buffer.lock().await;
        let mut ready = self.recv_ready.lock().await;
        
        loop {
            let expected = self.recv_sequence.load(Ordering::SeqCst);
            
            // Find and remove the expected sequence
            if let Some(pos) = recv_buf.iter().position(|(seq, _)| *seq == expected) {
                let (_, data) = recv_buf.remove(pos).unwrap();
                ready.push_back(data);
                self.recv_sequence.fetch_add(1, Ordering::SeqCst);
            } else {
                break;
            }
        }
    }

    /// Read data from the stream (async, waits if no data available)
    pub async fn recv(&self) -> Option<Bytes> {
        loop {
            {
                let mut ready = self.recv_ready.lock().await;
                if let Some(data) = ready.pop_front() {
                    return Some(data);
                }
                
                // Check if stream is closed
                if self.remote_finished.load(Ordering::SeqCst) {
                    return None;
                }
            }
            
            // Wait for new data
            self.recv_notify.notified().await;
        }
    }

    /// Try to read data without waiting
    pub async fn try_recv(&self) -> Option<Bytes> {
        self.recv_ready.lock().await.pop_front()
    }

    /// Mark local side as finished (no more data to send)
    pub async fn finish(&self) {
        self.local_finished.store(true, Ordering::SeqCst);
        self.update_state().await;
    }

    /// Mark remote side as finished
    pub async fn on_remote_finish(&self) {
        self.remote_finished.store(true, Ordering::SeqCst);
        self.recv_notify.notify_waiters();
        self.update_state().await;
    }

    /// Update stream state based on finish flags
    async fn update_state(&self) {
        let local = self.local_finished.load(Ordering::SeqCst);
        let remote = self.remote_finished.load(Ordering::SeqCst);
        
        let new_state = match (local, remote) {
            (true, true) => StreamState::Closed,
            (true, false) => StreamState::HalfClosedLocal,
            (false, true) => StreamState::HalfClosedRemote,
            (false, false) => StreamState::Open,
        };
        
        *self.state.lock().await = new_state;
    }

    /// Get number of pending send chunks
    pub async fn pending_send_count(&self) -> usize {
        self.send_buffer.lock().await.len()
    }

    /// Get number of pending receive chunks
    pub async fn pending_recv_count(&self) -> usize {
        self.recv_ready.lock().await.len()
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.local_finished.load(Ordering::SeqCst) && 
        self.remote_finished.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("id", &self.id)
            .field("send_seq", &self.send_sequence.load(Ordering::Relaxed))
            .field("recv_seq", &self.recv_sequence.load(Ordering::Relaxed))
            .field("priority", &self.priority.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stream_send_recv() {
        let stream = Stream::new(1);
        
        // Send data
        stream.send_reliable(Bytes::from("hello")).await;
        stream.send_reliable(Bytes::from("world")).await;
        
        // Check pending
        assert_eq!(stream.pending_send_count().await, 2);
        
        // Poll send twice, the second should be None because it's already sent and hasn't timed out
        let (seq, data, is_reliable) = stream.poll_send().await.unwrap();
        assert_eq!(seq, 0);
        assert_eq!(data, Bytes::from("hello"));
        assert!(is_reliable);
        
        let (seq2, data2, is_reliable2) = stream.poll_send().await.unwrap();
        assert_eq!(seq2, 1);
        assert_eq!(data2, Bytes::from("world"));
        assert!(is_reliable2);
        
        assert!(stream.poll_send().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_retransmission() {
        // We use tokio::time::pause to mock time and test timeout
        tokio::time::pause();
        let stream = Stream::new(1);
        
        stream.send_reliable(Bytes::from("hello")).await;
        
        // First send
        let (seq, _, is_reliable) = stream.poll_send().await.unwrap();
        assert_eq!(seq, 0);
        assert!(is_reliable);
        
        // Immediate poll should be None
        assert!(stream.poll_send().await.is_none());
        
        // Advance time by 400ms (less than timeout)
        tokio::time::advance(std::time::Duration::from_millis(400)).await;
        assert!(stream.poll_send().await.is_none());
        
        // Advance time past 500ms
        tokio::time::advance(std::time::Duration::from_millis(150)).await;
        
        // Now it should retransmit
        let (seq2, data2, is_reliable2) = stream.poll_send().await.unwrap();
        assert_eq!(seq2, 0);
        assert_eq!(data2, Bytes::from("hello"));
        assert!(is_reliable2);
        
        // Ack it
        let acked = stream.ack(0).await;
        assert!(acked.is_some());
        
        // Poll again - queue is empty
        assert!(stream.poll_send().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_in_order_receive() {
        let stream = Stream::new(1);
        
        // Receive in order
        stream.on_receive(0, Bytes::from("first")).await;
        stream.on_receive(1, Bytes::from("second")).await;
        
        assert_eq!(stream.try_recv().await, Some(Bytes::from("first")));
        assert_eq!(stream.try_recv().await, Some(Bytes::from("second")));
        assert_eq!(stream.try_recv().await, None);
    }

    #[tokio::test]
    async fn test_stream_out_of_order_receive() {
        let stream = Stream::new(1);
        
        // Receive out of order
        stream.on_receive(1, Bytes::from("second")).await;
        stream.on_receive(0, Bytes::from("first")).await;
        
        // Should be reordered
        assert_eq!(stream.try_recv().await, Some(Bytes::from("first")));
        assert_eq!(stream.try_recv().await, Some(Bytes::from("second")));
    }

    #[tokio::test]
    async fn test_stream_state() {
        let stream = Stream::new(1);
        
        assert_eq!(stream.state().await, StreamState::Open);
        
        stream.finish().await;
        assert_eq!(stream.state().await, StreamState::HalfClosedLocal);
        
        stream.on_remote_finish().await;
        assert_eq!(stream.state().await, StreamState::Closed);
        assert!(stream.is_closed());
    }

    #[tokio::test]
    async fn test_stream_backpressure() {
        let stream = Stream::new(1);
        
        // Fill the buffer
        for _ in 0..MAX_PENDING_PACKETS {
            stream.send_reliable(Bytes::from("data")).await;
        }
        
        assert_eq!(stream.pending_send_count().await, MAX_PENDING_PACKETS);
        
        // Try to send one more with timeout
        let send_future = stream.send_reliable(Bytes::from("blocked"));
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), send_future).await;
        assert!(result.is_err(), "Send should have blocked");
        
        // Ack one
        stream.ack(0).await;
        
        // Now it should succeed
        let send_future = stream.send_reliable(Bytes::from("resumed"));
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), send_future).await;
        assert!(result.is_ok(), "Send should have succeeded after ack");
        assert_eq!(stream.pending_send_count().await, MAX_PENDING_PACKETS);
    }
}
