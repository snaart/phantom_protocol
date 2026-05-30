//! Phantom Transport Core - Types
//!
//! Core types for the Phantom Universal Transport protocol:
//! - SessionId (256-bit, salt for encryption)
//! - StreamId, SequenceNumber
//! - PacketHeader, PacketFlags
//! - PhantomPacket (the single on-wire data packet)

#![allow(unused_assignments)]

use alkahest::alkahest;
use borsh::{BorshDeserialize, BorshSerialize};
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

/// The sole on-wire packet-header version byte. Pinned — the wire format is not
/// negotiated (pre-1.0, no users); a decoder rejects anything else. It exists as
/// a tamper-check anchor and a hook for a future, deliberate version increment.
pub const WIRE_VERSION: u8 = 1;

/// Packet flags bitfield (16-bit).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[alkahest(Formula, SerializeRef, Deserialize)]
pub struct PacketFlags(pub u16);

impl PacketFlags {
    /// Requires acknowledgment
    pub const RELIABLE: u16 = 0x0001;
    /// This is an ACK packet
    pub const ACK: u16 = 0x0002;
    /// Stream finished
    pub const FIN: u16 = 0x0004;
    /// Fire-and-forget (no retransmission)
    pub const UNRELIABLE: u16 = 0x0008;
    /// High priority (voice, video frames)
    pub const PRIORITY: u16 = 0x0010;
    /// Payload is encrypted
    pub const ENCRYPTED: u16 = 0x0020;
    /// Payload is compressed
    pub const COMPRESSED: u16 = 0x0040;
    /// Control message (handshake, migration)
    pub const CONTROL: u16 = 0x0080;
    /// Sender is rekeying — receiver must derive the next AEAD key from the
    /// resumption-secret HKDF chain before decrypting this packet (Phase 1.5).
    pub const REKEY: u16 = 0x0100;
    /// Path-validation challenge / response packet for multi-path migration
    /// (Phase 4.2). Payload carries the 32-byte challenge or response.
    pub const PATH_VALIDATION: u16 = 0x0200;
    /// Payload is a coalesced bundle of inner packets in
    /// `[count: u16][len1: u16][payload1]...` format (Phase 2.5).
    pub const COALESCED: u16 = 0x0400;
    /// Per-stream flow control update (Phase 4.3). Payload is a
    /// big-endian `u32` carrying the receiver's newly-available
    /// window in bytes (absolute window size, NOT a delta — simpler
    /// and self-correcting under packet loss).
    pub const WINDOW_UPDATE: u16 = 0x0800;
    // 0x1000 .. 0x8000 — reserved for future amendments.

    /// Create new flags with no bits set
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create flags with specific bits
    pub const fn new(bits: u16) -> Self {
        Self(bits)
    }

    /// Check if flag is set
    #[inline]
    pub const fn contains(&self, flag: u16) -> bool {
        (self.0 & flag) == flag
    }

    /// Set a flag
    #[inline]
    pub fn set(&mut self, flag: u16) {
        self.0 |= flag;
    }

    /// Clear a flag
    #[inline]
    pub fn clear(&mut self, flag: u16) {
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

    /// Check if this is a rekey packet
    #[inline]
    pub const fn is_rekey(&self) -> bool {
        self.contains(Self::REKEY)
    }
}

impl fmt::Debug for PacketFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.contains(Self::RELIABLE) {
            flags.push("RELIABLE");
        }
        if self.contains(Self::ACK) {
            flags.push("ACK");
        }
        if self.contains(Self::FIN) {
            flags.push("FIN");
        }
        if self.contains(Self::UNRELIABLE) {
            flags.push("UNRELIABLE");
        }
        if self.contains(Self::PRIORITY) {
            flags.push("PRIORITY");
        }
        if self.contains(Self::ENCRYPTED) {
            flags.push("ENCRYPTED");
        }
        if self.contains(Self::COMPRESSED) {
            flags.push("COMPRESSED");
        }
        if self.contains(Self::CONTROL) {
            flags.push("CONTROL");
        }
        if self.contains(Self::REKEY) {
            flags.push("REKEY");
        }
        if self.contains(Self::PATH_VALIDATION) {
            flags.push("PATH_VALIDATION");
        }
        if self.contains(Self::COALESCED) {
            flags.push("COALESCED");
        }
        if self.contains(Self::WINDOW_UPDATE) {
            flags.push("WINDOW_UPDATE");
        }
        write!(f, "PacketFlags({})", flags.join("|"))
    }
}

/// Packet header — 45 bytes on the wire (the AEAD AAD).
///
/// The fields below are in **declaration** order; the on-wire byte order is
/// different. `alkahest` emits a struct's fields in reverse declaration order,
/// integers little-endian, and byte arrays reversed — so `path_id` is the first
/// wire byte and `version` the last. The exact offsets are frozen by
/// `core/tests/wire_vectors/packet_header.bin` and documented in
/// `docs/protocol/PROTOCOL.md` § 4.2. Tamper resistance does not depend on byte
/// position: the whole 45-byte header is the AEAD AAD, so flipping any byte
/// (`version` included) fails decryption.
/// - version: u8 — pinned [`WIRE_VERSION`]; the recv path drops a frame whose
///   `version != WIRE_VERSION` after deserialising the packet.
/// - session_id: [u8; 32] — 256-bit session identifier (salt)
/// - stream_id: u16 — stream within session (0 = control)
/// - sequence: u32 — per-stream sequence number
/// - flags: u16 — packet flags
/// - ack_delay: u16 — delay before ACK was sent, microseconds
/// - epoch: u8 — rekey generation (0 at session establishment; bumps on each
///   in-band rekey signal). Receiver derives the corresponding AEAD key.
/// - path_id: u8 — which leg / path this packet was sent over. 0 = default.
#[derive(Clone, Copy, PartialEq, Eq)]
#[alkahest(Formula, SerializeRef, Deserialize)]
#[repr(C)]
pub struct PacketHeader {
    /// On-wire packet-format version. Pinned to [`WIRE_VERSION`]. Declared
    /// first, but alkahest emits it as the **last** of the 45 header bytes
    /// (reverse field order); it is part of the AEAD AAD wherever it lands.
    pub version: u8,
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
    /// Rekey generation. Zero at session establishment, incremented in lock-
    /// step on each in-band rekey (Phase 1.5).
    pub epoch: u8,
    /// Multi-path leg identifier (Phase 4.2). 0 = single-leg default.
    pub path_id: u8,
}

impl PacketHeader {
    /// Header size in bytes (serialised wire length).
    pub const SIZE: usize = 45;

    /// Create a new packet header (version = [`WIRE_VERSION`], epoch = 0,
    /// path_id = 0, ack_delay = 0).
    pub fn new(
        session_id: SessionId,
        stream_id: StreamId,
        sequence: SequenceNumber,
        flags: PacketFlags,
    ) -> Self {
        Self {
            version: WIRE_VERSION,
            session_id,
            stream_id,
            sequence,
            flags,
            ack_delay: 0,
            epoch: 0,
            path_id: 0,
        }
    }

    /// Set the rekey epoch — used by `Session::rekey` (Phase 1.5).
    pub fn with_epoch(mut self, epoch: u8) -> Self {
        self.epoch = epoch;
        self
    }

    /// Set the path id — used by the multi-path scheduler (Phase 4.2).
    pub fn with_path_id(mut self, path_id: u8) -> Self {
        self.path_id = path_id;
        self
    }
}

impl fmt::Debug for PacketHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketHeader")
            .field("version", &self.version)
            .field("session", &self.session_id)
            .field("stream", &self.stream_id)
            .field("seq", &self.sequence)
            .field("flags", &self.flags)
            .field("epoch", &self.epoch)
            .field("path_id", &self.path_id)
            .finish()
    }
}

/// Full packet with header and payload — the single on-wire data packet.
#[derive(Clone, PartialEq, Eq)]
#[alkahest(Formula, SerializeRef, Deserialize)]
pub struct PhantomPacket {
    /// Packet header (45 bytes)
    pub header: PacketHeader,
    /// Encrypted payload (or coalesced bundle if `COALESCED` flag set)
    pub payload: Vec<u8>,
    /// TLV headroom for forward-compatible amendments (packet-number / SACK
    /// fields) without a layout change. Old peers deserialize this as an empty
    /// `Vec` and ignore it.
    pub extensions: Vec<u8>,
}

impl PhantomPacket {
    /// Create a new packet (extensions empty by default)
    pub fn new(header: PacketHeader, payload: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            extensions: Vec::new(),
        }
    }

    /// Create an ACK packet: `ACK` flag only, empty payload, unencrypted.
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

    /// Total wire size including extensions
    pub fn wire_size(&self) -> usize {
        PacketHeader::SIZE + self.payload.len() + self.extensions.len()
    }
}

impl fmt::Debug for PhantomPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhantomPacket")
            .field("header", &self.header)
            .field("payload_len", &self.payload.len())
            .field("extensions_len", &self.extensions.len())
            .finish()
    }
}

/// Control message types for session management
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
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
    fn flags_bit_assignments() {
        assert_eq!(PacketFlags::RELIABLE, 0x0001);
        assert_eq!(PacketFlags::ENCRYPTED, 0x0020);
        assert_eq!(PacketFlags::CONTROL, 0x0080);
        assert_eq!(PacketFlags::REKEY, 0x0100);
        assert_eq!(PacketFlags::PATH_VALIDATION, 0x0200);
        assert_eq!(PacketFlags::COALESCED, 0x0400);
        assert_eq!(PacketFlags::WINDOW_UPDATE, 0x0800);
    }

    #[test]
    fn flags_contains_set_clear() {
        let mut f = PacketFlags::empty();
        assert!(!f.is_reliable());
        assert!(!f.is_rekey());
        f.set(PacketFlags::RELIABLE | PacketFlags::REKEY);
        assert!(f.is_reliable());
        assert!(f.is_rekey());
        f.clear(PacketFlags::REKEY);
        assert!(f.is_reliable());
        assert!(!f.is_rekey());
    }

    #[test]
    fn packet_header_serializes_to_45_bytes() {
        assert_eq!(PacketHeader::SIZE, 45);
        let header = PacketHeader::new(
            SessionId::from_bytes([0u8; 32]),
            1,
            1,
            PacketFlags::new(PacketFlags::ENCRYPTED),
        );
        let mut buf = Vec::new();
        let (size, _) = alkahest::serialize_to_vec::<PacketHeader, _>(&header, &mut buf);
        assert_eq!(
            size,
            PacketHeader::SIZE,
            "the serialised header (= AEAD AAD) must be exactly 45 bytes"
        );
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
    fn packet_roundtrip_preserves_fields() {
        let session_id = SessionId::random();
        let header = PacketHeader::new(
            session_id,
            7,
            42,
            PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
        )
        .with_epoch(3)
        .with_path_id(1);
        let packet = PhantomPacket::new(header, vec![0xCA, 0xFE, 0xBA, 0xBE]);

        let mut bytes = Vec::new();
        let (size, _) = alkahest::serialize_to_vec::<PhantomPacket, _>(&packet, &mut bytes);
        let decoded = alkahest::deserialize::<PhantomPacket, PhantomPacket>(&bytes[..size])
            .expect("roundtrip");
        assert_eq!(decoded.header.version, WIRE_VERSION);
        assert_eq!(decoded.header.stream_id, 7);
        assert_eq!(decoded.header.sequence, 42);
        assert_eq!(decoded.header.epoch, 3);
        assert_eq!(decoded.header.path_id, 1);
        assert!(decoded.header.flags.is_reliable());
        assert!(decoded.header.flags.contains(PacketFlags::ENCRYPTED));
        assert_eq!(decoded.payload, vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn extensions_preserved_on_roundtrip() {
        let session_id = SessionId::random();
        let mut packet = PhantomPacket::new(
            PacketHeader::new(
                session_id,
                1,
                1,
                PacketFlags::new(PacketFlags::CONTROL | PacketFlags::RELIABLE),
            ),
            vec![1, 2, 3],
        );
        packet.extensions = vec![0xFF, 0x01, 0x00, 0x04, b't', b'e', b's', b't'];

        let mut bytes = Vec::new();
        let (size, _) = alkahest::serialize_to_vec::<PhantomPacket, _>(&packet, &mut bytes);
        let deser = alkahest::deserialize::<PhantomPacket, PhantomPacket>(&bytes[..size])
            .expect("deserialize failed");
        assert_eq!(
            deser.extensions,
            vec![0xFF, 0x01, 0x00, 0x04, b't', b'e', b's', b't']
        );
    }
}
