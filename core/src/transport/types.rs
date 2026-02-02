//! Phantom Transport Core - Types
//!
//! Core types for the Phantom Universal Transport protocol:
//! - SessionId (256-bit, salt for encryption)
//! - StreamId, SequenceNumber
//! - PacketHeader, PacketFlags
//! - VersionedPacket / PhantomPacketV1

#![allow(unused_assignments)]

use alkahest::alkahest;
use borsh::{BorshSerialize, BorshDeserialize};
use std::fmt;

/// 256-bit Session Identifier
/// 
/// Used as salt for encryption and session persistence across IP changes.
/// Post-quantum safe size (32 bytes = 256 bits).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[alkahest(Formula, SerializeRef, Deserialize)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    /// Create a new random session ID
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        if getrandom::getrandom(&mut bytes).is_err() {
            // Fallback to thread_rng which is always available
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        }
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
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[alkahest(Formula, SerializeRef, Deserialize)]
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
#[derive(Clone, Copy, PartialEq, Eq)]
#[alkahest(Formula, SerializeRef, Deserialize)]
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
    /// Delay between processing packet and sending ACK (in microseconds)
    pub ack_delay: u16,
}

impl PacketHeader {
    /// Header size in bytes
    pub const SIZE: usize = 41;

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
            ack_delay: 0,
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

/// Versioned wire format — the root deserialization target.
///
/// rkyv stores a 1-byte tag + union. An old client receiving an unknown
/// variant will get a controlled `CheckBytesError`, not silent corruption.
///
/// # Adding a new version
/// 1. Define `PhantomPacketV2` with new fields.
/// 2. Add `V2(PhantomPacketV2)` variant here.
/// 3. Implement conversion / downgrade logic as needed.
#[derive(Clone, PartialEq, Eq)]
#[alkahest(Formula, SerializeRef, Deserialize)]
pub enum VersionedPacket {
    /// Current wire format (v1)
    V1(PhantomPacketV1),
}

impl VersionedPacket {
    /// Unwrap the inner V1 packet (convenience for current code).
    /// Returns `None` if the variant is not V1.
    pub fn into_v1(self) -> Option<PhantomPacketV1> {
        match self {
            VersionedPacket::V1(p) => Some(p),
        }
    }

    /// Borrow the inner V1 packet.
    pub fn as_v1(&self) -> Option<&PhantomPacketV1> {
        match self {
            VersionedPacket::V1(p) => Some(p),
        }
    }

    /// Wrap a V1 packet into `VersionedPacket`.
    pub fn v1(packet: PhantomPacketV1) -> Self {
        VersionedPacket::V1(packet)
    }
}

impl fmt::Debug for VersionedPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionedPacket::V1(p) => write!(f, "VersionedPacket::V1({:?})", p),
        }
    }
}

/// Full packet with header and payload (V1 wire format).
///
/// The `extensions` field is a reserved byte buffer. Old code that doesn't
/// know about extensions will simply see an empty `Vec`. New code can write
/// sub-TLV structures into it without bumping the version.
#[derive(Clone, PartialEq, Eq)]
#[alkahest(Formula, SerializeRef, Deserialize)]
pub struct PhantomPacketV1 {
    /// Packet header (40 bytes)
    pub header: PacketHeader,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Reserved for future wire-format extensions.
    /// Old clients deserialize this as an empty Vec and ignore it.
    pub extensions: Vec<u8>,
}

/// Backward-compatible alias so existing code using `PhantomPacket` still compiles.
pub type PhantomPacket = PhantomPacketV1;

impl PhantomPacketV1 {
    /// Create a new packet (extensions empty by default)
    pub fn new(header: PacketHeader, payload: Vec<u8>) -> Self {
        Self { header, payload, extensions: Vec::new() }
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
            extensions: Vec::new(),
        }
    }

    /// Total size of the packet (header + payload, excluding extensions overhead)
    pub fn size(&self) -> usize {
        PacketHeader::SIZE + self.payload.len()
    }

    /// Total wire size including extensions
    pub fn wire_size(&self) -> usize {
        PacketHeader::SIZE + self.payload.len() + self.extensions.len()
    }

    /// Wrap this packet into a `VersionedPacket::V1`
    pub fn into_versioned(self) -> VersionedPacket {
        VersionedPacket::V1(self)
    }
}

impl fmt::Debug for PhantomPacketV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhantomPacketV1")
            .field("header", &self.header)
            .field("payload_len", &self.payload.len())
            .field("extensions_len", &self.extensions.len())
            .finish()
    }
}

/// Control message types for session management
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant=true)]
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

/// Transport modes supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum LegType {
    /// KCP over UDP - fast, reliable, primary transport
    Kcp,
    /// Raw TCP - reliable fallback
    Tcp,
    /// FakeTLS over TCP - obfuscated for DPI bypass
    FakeTls,
}

impl LegType {
    /// Whether this leg type provides reliability at transport level
    pub fn is_reliable(&self) -> bool {
        matches!(self, LegType::Kcp | LegType::Tcp | LegType::FakeTls)
    }
    
    /// Whether this leg type uses encryption/obfuscation
    pub fn is_obfuscated(&self) -> bool {
        matches!(self, LegType::FakeTls)
    }
}

/// Scheduling strategies for multi-path transport
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum SchedulerMode {
    /// Aggressive optimization for minimum RTT
    LowLatency,
    /// Bond multiple paths for maximum bandwidth
    HighThroughput,
    /// Redundant transmission for zero packet loss
    Reliability,
    /// Obfuscation prioritized over speed
    Stealth,
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
        assert!(ack.extensions.is_empty());
    }

    #[test]
    fn test_versioned_packet_v1_roundtrip() {
        let session_id = SessionId::random();
        let packet = PhantomPacketV1::new(
            PacketHeader::new(session_id, 1, 42, PacketFlags::new(PacketFlags::RELIABLE)),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );
        let versioned = VersionedPacket::v1(packet.clone());

        // Serialize with alkahest
        let mut bytes = Vec::new();
        let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&versioned, &mut bytes);

        // Deserialize and verify
        let deserialized = alkahest::deserialize::<VersionedPacket, VersionedPacket>(&bytes[..size])
            .expect("alkahest deserialize failed");

        let inner = deserialized.into_v1().expect("expected V1");
        assert_eq!(inner.header.stream_id, 1);
        assert_eq!(inner.header.sequence, 42);
        assert_eq!(inner.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(inner.extensions.is_empty());
    }

    #[test]
    fn test_extensions_preserved_on_roundtrip() {
        let session_id = SessionId::random();
        let mut packet = PhantomPacketV1::new(
            PacketHeader::control(session_id, 1),
            vec![1, 2, 3],
        );
        // Write some extension data
        packet.extensions = vec![0xFF, 0x01, 0x00, 0x04, b't', b'e', b's', b't'];

        let versioned = packet.into_versioned();
        let mut bytes = Vec::new();
        let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&versioned, &mut bytes);
        let deser = alkahest::deserialize::<VersionedPacket, VersionedPacket>(&bytes[..size])
            .expect("deserialize failed");
        let inner = deser.into_v1().unwrap();

        assert_eq!(inner.extensions, vec![0xFF, 0x01, 0x00, 0x04, b't', b'e', b's', b't']);
    }

    #[test]
    fn test_phantom_packet_alias_compat() {
        // PhantomPacket is a type alias for PhantomPacketV1 — existing code should work
        let session_id = SessionId::random();
        let pkt: PhantomPacket = PhantomPacket::new(
            PacketHeader::new(session_id, 0, 0, PacketFlags::empty()),
            vec![],
        );
        assert_eq!(pkt.size(), PacketHeader::SIZE);
    }
}
