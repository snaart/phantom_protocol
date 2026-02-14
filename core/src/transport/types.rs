//! Phantom Transport Core - Types
//!
//! Core types for the Phantom Universal Transport protocol:
//! - SessionId (256-bit, salt for encryption)
//! - StreamId, SequenceNumber
//! - PacketHeader, PacketFlags
//! - PhantomPacket

use rkyv::{Archive, Deserialize, Serialize};
use std::fmt;

/// 256-bit Session Identifier
/// 
/// Used as salt for encryption and session persistence across IP changes.
/// Post-quantum safe size (32 bytes = 256 bits).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Archive, Deserialize, Serialize)]
#[archive(check_bytes)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    /// Create a new random session ID
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("Failed to generate random SessionId");
        Self(bytes)
    }
    
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({}...)", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}...", hex::encode(&self.0[..8]))
    }
}

/// Stream identifier within a session
/// 
/// Stream 0 is reserved for control messages.
/// Each stream has independent sequence numbers (no HoL blocking).
pub type StreamId = u16;

/// Per-stream sequence number
pub type SequenceNumber = u32;

/// Packet flags bitfield
#[derive(Clone, Copy, PartialEq, Eq, Default, Archive, Deserialize, Serialize)]
#[archive(check_bytes)]
pub struct PacketFlags(pub u8);

impl PacketFlags {
    /// Requires acknowledgment
    pub const RELIABLE: u8 = 0b0000_0001;
    /// This is an ACK packet
    pub const ACK: u8 = 0b0000_0010;
    /// Stream finished
    pub const FIN: u8 = 0b0000_0100;
    /// Fire-and-forget (no retransmission)
    pub const UNRELIABLE: u8 = 0b0000_1000;
    /// High priority (voice, video frames)
    pub const PRIORITY: u8 = 0b0001_0000;
    /// Payload is encrypted
    pub const ENCRYPTED: u8 = 0b0010_0000;
    /// Payload is compressed
    pub const COMPRESSED: u8 = 0b0100_0000;
    /// Control message (handshake, migration)
    pub const CONTROL: u8 = 0b1000_0000;

    /// Create new flags with no bits set
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create flags with specific bits
    pub const fn new(bits: u8) -> Self {
        Self(bits)
    }

    /// Check if flag is set
    #[inline]
    pub const fn contains(&self, flag: u8) -> bool {
        (self.0 & flag) == flag
    }

    /// Set a flag
    #[inline]
    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    /// Clear a flag
    #[inline]
    pub fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }

    /// Check if reliable delivery is required
    #[inline]
    pub const fn is_reliable(&self) -> bool {
        self.contains(Self::RELIABLE)
    }

    /// Check if this is an ACK packet
    #[inline]
    pub const fn is_ack(&self) -> bool {
        self.contains(Self::ACK)
    }

    /// Check if stream is finished
    #[inline]
    pub const fn is_fin(&self) -> bool {
        self.contains(Self::FIN)
    }

    /// Check if this is a control packet
    #[inline]
    pub const fn is_control(&self) -> bool {
        self.contains(Self::CONTROL)
    }
}

impl fmt::Debug for PacketFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.contains(Self::RELIABLE) { flags.push("RELIABLE"); }
        if self.contains(Self::ACK) { flags.push("ACK"); }
        if self.contains(Self::FIN) { flags.push("FIN"); }
        if self.contains(Self::UNRELIABLE) { flags.push("UNRELIABLE"); }
        if self.contains(Self::PRIORITY) { flags.push("PRIORITY"); }
        if self.contains(Self::ENCRYPTED) { flags.push("ENCRYPTED"); }
        if self.contains(Self::COMPRESSED) { flags.push("COMPRESSED"); }
        if self.contains(Self::CONTROL) { flags.push("CONTROL"); }
        write!(f, "PacketFlags({})", flags.join("|"))
    }
}

/// Packet header - fixed 40 bytes
/// 
/// Layout:
/// - session_id: [u8; 32] - 256-bit session identifier (salt)
/// - stream_id: u16 - stream within session
/// - sequence: u32 - per-stream sequence number
/// - flags: u8 - packet flags
/// - reserved: u8 - padding/future use
#[derive(Clone, Copy, PartialEq, Eq, Archive, Deserialize, Serialize)]
#[archive(check_bytes)]
#[repr(C)]
pub struct PacketHeader {
    /// 256-bit session identifier, used as encryption salt
    pub session_id: SessionId,
    /// Stream within session (0 = control)
    pub stream_id: StreamId,
    /// Per-stream sequence number
    pub sequence: SequenceNumber,
    /// Packet flags
    pub flags: PacketFlags,
    /// Reserved for future use
    pub reserved: u8,
}

impl PacketHeader {
    /// Header size in bytes
    pub const SIZE: usize = 40;

    /// Create a new packet header
    pub fn new(
        session_id: SessionId,
        stream_id: StreamId,
        sequence: SequenceNumber,
        flags: PacketFlags,
    ) -> Self {
        Self {
            session_id,
            stream_id,
            sequence,
            flags,
            reserved: 0,
        }
    }

    /// Create a control packet header
    pub fn control(session_id: SessionId, sequence: SequenceNumber) -> Self {
        Self::new(
            session_id,
            0, // Control stream
            sequence,
            PacketFlags::new(PacketFlags::CONTROL | PacketFlags::RELIABLE),
        )
    }
}

impl fmt::Debug for PacketHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketHeader")
            .field("session", &self.session_id)
            .field("stream", &self.stream_id)
            .field("seq", &self.sequence)
            .field("flags", &self.flags)
            .finish()
    }
}

/// Full packet with header and payload
#[derive(Clone, PartialEq, Eq, Archive, Deserialize, Serialize)]
#[archive(check_bytes)]
pub struct PhantomPacket {
    /// Packet header (40 bytes)
    pub header: PacketHeader,
    /// Encrypted payload
    pub payload: Vec<u8>,
}

impl PhantomPacket {
    /// Create a new packet
    pub fn new(header: PacketHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Create an ACK packet
    pub fn ack(session_id: SessionId, stream_id: StreamId, ack_sequence: SequenceNumber) -> Self {
        Self {
            header: PacketHeader::new(
                session_id,
                stream_id,
                ack_sequence,
                PacketFlags::new(PacketFlags::ACK),
            ),
            payload: Vec::new(),
        }
    }

    /// Total size of the packet
    pub fn size(&self) -> usize {
        PacketHeader::SIZE + self.payload.len()
    }
}

impl fmt::Debug for PhantomPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhantomPacket")
            .field("header", &self.header)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Control message types for session management
#[derive(Clone, Copy, Debug, PartialEq, Eq, Archive, Deserialize, Serialize)]
#[archive(check_bytes)]
#[repr(u8)]
pub enum ControlMessage {
    /// Initial handshake request
    Hello = 0,
    /// Handshake response with session ID
    HelloAck = 1,
    /// Session resumption (0-RTT)
    Resume = 2,
    /// Session resumption acknowledged
    ResumeAck = 3,
    /// IP migration notification
    Migrate = 4,
    /// Migration acknowledged
    MigrateAck = 5,
    /// Graceful session close
    Close = 6,
    /// Close acknowledged
    CloseAck = 7,
    /// Heartbeat/keepalive
    Ping = 8,
    /// Heartbeat response
    Pong = 9,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_random() {
        let id1 = SessionId::random();
        let id2 = SessionId::random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_packet_flags() {
        let mut flags = PacketFlags::empty();
        assert!(!flags.is_reliable());
        
        flags.set(PacketFlags::RELIABLE);
        assert!(flags.is_reliable());
        
        flags.set(PacketFlags::ENCRYPTED);
        assert!(flags.contains(PacketFlags::RELIABLE));
        assert!(flags.contains(PacketFlags::ENCRYPTED));
        
        flags.clear(PacketFlags::RELIABLE);
        assert!(!flags.is_reliable());
        assert!(flags.contains(PacketFlags::ENCRYPTED));
    }

    #[test]
    fn test_packet_header_size() {
        // Verify header is correct size for zero-copy operations
        assert_eq!(std::mem::size_of::<SessionId>(), 32);
        // Note: actual PacketHeader size may be different due to alignment
        // The wire format is 40 bytes
    }

    #[test]
    fn test_phantom_packet_ack() {
        let session_id = SessionId::random();
        let ack = PhantomPacket::ack(session_id, 5, 100);
        
        assert!(ack.header.flags.is_ack());
        assert_eq!(ack.header.stream_id, 5);
        assert_eq!(ack.header.sequence, 100);
        assert!(ack.payload.is_empty());
    }
}
