//! Phantom Protocol - Types
//!
//! Core types for the Phantom Protocol:
//! - SessionId (256-bit, salt for encryption)
//! - StreamId, SequenceNumber
//! - PacketHeader, PacketFlags
//! - PhantomPacket (the single on-wire data packet)

use borsh::{BorshDeserialize, BorshSerialize};
use std::fmt;

/// 256-bit Session Identifier
///
/// Used as salt for encryption and session persistence across IP changes.
/// Post-quantum safe size (32 bytes = 256 bits).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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

/// Per-stream gap-free reliable-data offset (A.5). Stays `u32`.
pub type SequenceNumber = u32;

/// Per-direction monotonic AEAD packet number (① — Phase 4). Feeds the AEAD
/// nonce and the per-direction replay window. `u64` so it never wraps within a
/// session — this is what retires the C1 forced-rekey watermark.
pub type PacketNumber = u64;

/// The sole on-wire packet-header version byte. Pinned — the wire format is not
/// negotiated (pre-1.0, no users); a decoder rejects anything else. `4` since
/// T4.6 added QUIC-style header protection (RFC 9001 §5.4): the header was
/// reordered so the 14 variable bytes (`packet_number ‖ flags ‖ stream_id ‖
/// epoch ‖ path_id`) are contiguous at offset `[33..47]` and HP-masked on the
/// wire, leaving only `version ‖ session_id` (the routing CID) in the clear
/// (see PROTOCOL.md § 4.2). Phase 4 (`3`) had widened the packet number to `u64`,
/// dropped the dead `ack_delay`, and moved the nonce to `prefix‖packet_number`.
pub const WIRE_VERSION: u8 = 4;

/// Wire offset where the header-protected region begins — immediately after the
/// cleartext `version(1) ‖ session_id(32)` routing prefix (T4.6). Everything at
/// `[HP_PROTECTED_OFFSET..PacketHeader::SIZE]` is XOR-masked on the wire.
pub const HP_PROTECTED_OFFSET: usize = 33;

/// Length of the header-protected region (`PacketHeader::SIZE - HP_PROTECTED_OFFSET`
/// = 14 bytes: `packet_number ‖ flags ‖ stream_id ‖ epoch ‖ path_id`). Matches
/// the HP mask length the [`HeaderProtector`] produces.
///
/// [`HeaderProtector`]: crate::crypto::header_protection::HeaderProtector
pub const HP_PROTECTED_LEN: usize = PacketHeader::SIZE - HP_PROTECTED_OFFSET;

/// Error decoding a packet header / packet from its on-wire bytes.
///
/// The explicit codec ([`PacketHeader::from_wire`] / [`PhantomPacket::from_wire`])
/// has exactly one failure mode: the buffer is shorter than the structure it
/// declares (a header underrun, or a length prefix that runs past the end of the
/// buffer). A malformed frame is dropped, never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The buffer is shorter than the declared structure.
    Truncated,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "truncated packet"),
        }
    }
}

impl std::error::Error for WireError {}

/// Packet flags bitfield (16-bit).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
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

/// Packet header — 47 bytes on the wire (the AEAD AAD).
///
/// Serialised by [`PacketHeader::to_wire`] as an explicit, fixed **big-endian**
/// (network byte order) image, `version` first. WIRE_VERSION 4 (T4.6) reorders
/// the fields so the 14 HP-protected bytes are a contiguous span at `[33..47]`,
/// after the cleartext routing prefix:
///
/// ```text
/// off  0  version        u8       (= WIRE_VERSION = 4)            CLEARTEXT
/// off  1  session_id     [u8;32]  (routing CID)                  CLEARTEXT
/// off 33  packet_number  u64 be   (① per-direction monotonic)    HP-MASKED ┐
/// off 41  flags          u16 be                                  HP-MASKED │
/// off 43  stream_id      u16 be                                  HP-MASKED │ [33..47]
/// off 45  epoch          u8                                      HP-MASKED │
/// off 46  path_id        u8                                      HP-MASKED ┘
/// ```
///
/// The `to_wire` image (the **cleartext** 47-byte header) is the AEAD AAD, so
/// flipping any byte (`version` included) fails decryption. On the wire the
/// `[33..47]` span is XOR-masked by the per-session [`HeaderProtector`] (a wire
/// mutation of the masked region unmasks to a wrong header → wrong AAD → AEAD
/// fails — no new oracle); the recv path reconstructs the cleartext header via
/// [`RawPacket::unmask_header`] before computing the AAD. `epoch`/`stream_id`/
/// `path_id` are authenticated in the AAD but NOT in the nonce (which is
/// `prefix‖packet_number`). The recv path also drops a frame whose
/// `version != WIRE_VERSION`. Frozen by `core/tests/wire_vectors/packet_header.bin`;
/// grammar in `docs/protocol/PROTOCOL.md` § 4.2.
///
/// [`HeaderProtector`]: crate::crypto::header_protection::HeaderProtector
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PacketHeader {
    /// On-wire packet-format version. Pinned to [`WIRE_VERSION`]; the first wire
    /// byte (see [`PacketHeader::to_wire`]).
    pub version: u8,
    /// 256-bit session identifier, used as encryption salt
    pub session_id: SessionId,
    /// Stream within session (0 = control)
    pub stream_id: StreamId,
    /// Per-direction monotonic AEAD packet number (① — Phase 4). Feeds the AEAD
    /// nonce and the per-direction replay window; assigned at send time.
    pub packet_number: PacketNumber,
    /// Packet flags
    pub flags: PacketFlags,
    /// Rekey generation. Zero at session establishment, incremented in lock-
    /// step on each in-band rekey (Phase 1.5).
    pub epoch: u8,
    /// Multi-path leg identifier (Phase 4.2). 0 = single-leg default.
    pub path_id: u8,
}

impl PacketHeader {
    /// Header size in bytes (serialised wire length).
    pub const SIZE: usize = 47;

    /// Create a new packet header (version = [`WIRE_VERSION`], epoch = 0,
    /// path_id = 0).
    pub fn new(
        session_id: SessionId,
        stream_id: StreamId,
        packet_number: PacketNumber,
        flags: PacketFlags,
    ) -> Self {
        Self {
            version: WIRE_VERSION,
            session_id,
            stream_id,
            packet_number,
            flags,
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

    /// Serialise to the fixed 47 on-wire bytes (big-endian, `version` first).
    /// This image is the AEAD AAD.
    pub fn to_wire(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0] = self.version;
        b[1..33].copy_from_slice(&self.session_id.0);
        // HP-protected region [33..47] — packet_number ‖ flags ‖ stream_id ‖
        // epoch ‖ path_id (WIRE_VERSION 4 layout; see the struct doc grammar).
        b[33..41].copy_from_slice(&self.packet_number.to_be_bytes());
        b[41..43].copy_from_slice(&self.flags.0.to_be_bytes());
        b[43..45].copy_from_slice(&self.stream_id.to_be_bytes());
        b[45] = self.epoch;
        b[46] = self.path_id;
        b
    }

    /// Parse a header from the first [`Self::SIZE`] bytes of `bytes`. Does not
    /// validate `version` — the recv path gates on it separately so the same
    /// parser serves both the version check and the codecs.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < Self::SIZE {
            return Err(WireError::Truncated);
        }
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&bytes[1..33]);
        Ok(Self {
            version: bytes[0],
            session_id: SessionId(session_id),
            // HP-protected region [33..47] — packet_number ‖ flags ‖ stream_id ‖
            // epoch ‖ path_id (WIRE_VERSION 4 layout).
            packet_number: u64::from_be_bytes([
                bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
                bytes[40],
            ]),
            flags: PacketFlags(u16::from_be_bytes([bytes[41], bytes[42]])),
            stream_id: u16::from_be_bytes([bytes[43], bytes[44]]),
            epoch: bytes[45],
            path_id: bytes[46],
        })
    }
}

impl fmt::Debug for PacketHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketHeader")
            .field("version", &self.version)
            .field("session", &self.session_id)
            .field("stream", &self.stream_id)
            .field("pn", &self.packet_number)
            .field("flags", &self.flags)
            .field("epoch", &self.epoch)
            .field("path_id", &self.path_id)
            .finish()
    }
}

/// Read a `u32`-big-endian length prefix at `*pos`, then that many bytes,
/// advancing `pos` past both. Bounds-checked (and overflow-safe on 32-bit
/// targets) so a hostile length prefix yields [`WireError::Truncated`], never an
/// out-of-bounds access.
fn read_length_prefixed(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, WireError> {
    let start = *pos;
    let len_end = start.checked_add(4).ok_or(WireError::Truncated)?;
    if len_end > bytes.len() {
        return Err(WireError::Truncated);
    }
    let len = u32::from_be_bytes([
        bytes[start],
        bytes[start + 1],
        bytes[start + 2],
        bytes[start + 3],
    ]) as usize;
    let data_end = len_end.checked_add(len).ok_or(WireError::Truncated)?;
    if data_end > bytes.len() {
        return Err(WireError::Truncated);
    }
    *pos = data_end;
    Ok(bytes[len_end..data_end].to_vec())
}

/// Full packet with header and payload — the single on-wire data packet.
#[derive(Clone, PartialEq, Eq)]
pub struct PhantomPacket {
    /// Packet header (47 bytes)
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
    pub fn ack(session_id: SessionId, stream_id: StreamId, ack_packet_number: u64) -> Self {
        Self {
            header: PacketHeader::new(
                session_id,
                stream_id,
                ack_packet_number,
                PacketFlags::new(PacketFlags::ACK),
            ),
            payload: Vec::new(),
            extensions: Vec::new(),
        }
    }

    /// Total wire size including extensions and the two `u32` length prefixes.
    pub fn wire_size(&self) -> usize {
        PacketHeader::SIZE + 8 + self.payload.len() + self.extensions.len()
    }

    /// Serialise to the on-wire bytes:
    /// `header(47) || payload_len:u32be || payload || ext_len:u32be || extensions`.
    ///
    /// This is the **cleartext** image (the AEAD AAD prefix). The data plane never
    /// puts these bytes on the wire directly — it calls [`Self::to_wire_masked`]
    /// to apply header protection. `to_wire` is retained for the AAD, the frozen
    /// wire-vectors, and handshake-adjacent / test paths.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.wire_size());
        b.extend_from_slice(&self.header.to_wire());
        b.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.payload);
        b.extend_from_slice(&(self.extensions.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.extensions);
        b
    }

    /// Serialise with header protection applied (T4.6): identical to [`Self::to_wire`],
    /// then the `[HP_PROTECTED_OFFSET..PacketHeader::SIZE]` region (the 14 bytes
    /// `packet_number ‖ flags ‖ stream_id ‖ epoch ‖ path_id`) is XOR-masked with
    /// the caller-supplied HP `mask`. The mask is computed from this packet's
    /// `payload` ciphertext by the session's `HeaderProtector` (`mask_send`); the
    /// cleartext `version ‖ session_id` routing prefix and the length-prefixed
    /// payload/extensions stay in the clear so the demux can route and the recv
    /// path can locate the ciphertext sample before unmasking. Only the first
    /// [`HP_PROTECTED_LEN`] bytes of `mask` are used; a shorter `mask` masks fewer
    /// bytes rather than panicking (the session always supplies a full 16-byte
    /// mask).
    pub fn to_wire_masked(&self, mask: &[u8]) -> Vec<u8> {
        let mut buf = self.to_wire();
        // zip stops at the shorter of the 14-byte region and `mask`, so a short
        // mask masks fewer bytes rather than panicking.
        for (b, m) in buf[HP_PROTECTED_OFFSET..PacketHeader::SIZE]
            .iter_mut()
            .zip(mask)
        {
            *b ^= *m;
        }
        buf
    }

    /// Parse a packet from its on-wire bytes — the inverse of [`Self::to_wire`].
    /// Any bytes past `extensions` are ignored (forward-compatibility headroom).
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let header = PacketHeader::from_wire(bytes)?;
        let mut pos = PacketHeader::SIZE;
        let payload = read_length_prefixed(bytes, &mut pos)?;
        let extensions = read_length_prefixed(bytes, &mut pos)?;
        Ok(Self {
            header,
            payload,
            extensions,
        })
    }
}

/// A partially-decoded v4 packet: the cleartext envelope (routing `version` +
/// `session_id`, plus the length-prefixed `payload` / `extensions`) with the
/// 14-byte header-protected region left **opaque**. The recv path produces this
/// from the raw wire bytes *before* it has the per-session HP key — it can route
/// on `session_id` and locate the ciphertext sample (`payload`) from the
/// cleartext length prefixes, then call [`RawPacket::unmask_header`] with the
/// mask computed from `payload` to recover the full [`PacketHeader`]. This is
/// the codec half of T4.6's header protection; the mask itself is computed by
/// the session's `HeaderProtector` (this module stays crypto-free).
#[derive(Clone, Debug)]
pub struct RawPacket {
    /// Cleartext wire version byte (`[0]`).
    pub version: u8,
    /// Cleartext routing session id / CID (`[1..33]`).
    pub session_id: SessionId,
    /// The still-masked header-protected region (wire `[33..47]`).
    masked_header: [u8; HP_PROTECTED_LEN],
    /// AEAD ciphertext (length-prefixed; cleartext on the wire).
    pub payload: Vec<u8>,
    /// Forward-compat TLV headroom (length-prefixed; cleartext on the wire).
    pub extensions: Vec<u8>,
}

impl RawPacket {
    /// Parse the cleartext envelope of a v4 wire packet, leaving the 14-byte
    /// HP-masked header region opaque. Bounds-checked exactly like
    /// [`PhantomPacket::from_wire`] — a short / hostile buffer yields
    /// [`WireError::Truncated`], never a panic.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < PacketHeader::SIZE {
            return Err(WireError::Truncated);
        }
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&bytes[1..HP_PROTECTED_OFFSET]);
        let mut masked_header = [0u8; HP_PROTECTED_LEN];
        masked_header.copy_from_slice(&bytes[HP_PROTECTED_OFFSET..PacketHeader::SIZE]);
        let mut pos = PacketHeader::SIZE;
        let payload = read_length_prefixed(bytes, &mut pos)?;
        let extensions = read_length_prefixed(bytes, &mut pos)?;
        Ok(Self {
            version: bytes[0],
            session_id: SessionId(session_id),
            masked_header,
            payload,
            extensions,
        })
    }

    /// Recover the full cleartext [`PacketHeader`] by XOR-ing the masked region
    /// with the caller-supplied HP `mask` (the session's
    /// `HeaderProtector::mask_recv` over `self.payload`). A `mask` shorter than
    /// [`HP_PROTECTED_LEN`] is rejected as [`WireError::Truncated`] rather than
    /// panicking (the session always supplies a full 16-byte mask).
    pub fn unmask_header(&self, mask: &[u8]) -> Result<PacketHeader, WireError> {
        if mask.len() < HP_PROTECTED_LEN {
            return Err(WireError::Truncated);
        }
        let mut hdr = [0u8; PacketHeader::SIZE];
        hdr[0] = self.version;
        hdr[1..HP_PROTECTED_OFFSET].copy_from_slice(&self.session_id.0);
        hdr[HP_PROTECTED_OFFSET..].copy_from_slice(&self.masked_header);
        for (h, m) in hdr[HP_PROTECTED_OFFSET..].iter_mut().zip(mask) {
            *h ^= *m;
        }
        PacketHeader::from_wire(&hdr)
    }

    /// Reassemble a full [`PhantomPacket`] from this raw envelope plus a recovered
    /// header, moving out `payload` / `extensions`.
    pub fn into_packet(self, header: PacketHeader) -> PhantomPacket {
        PhantomPacket {
            header,
            payload: self.payload,
            extensions: self.extensions,
        }
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
    /// PhantomUDP — native reliable transport over raw UDP (Phase 1).
    Udp,
}

impl LegType {
    /// Whether this leg type provides reliability at transport level
    pub fn is_reliable(&self) -> bool {
        matches!(
            self,
            LegType::Kcp | LegType::Tcp | LegType::FakeTls | LegType::Udp
        )
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
    fn packet_header_serializes_to_47_bytes() {
        assert_eq!(PacketHeader::SIZE, 47);
        let header = PacketHeader::new(
            SessionId::from_bytes([0u8; 32]),
            1,
            1,
            PacketFlags::new(PacketFlags::ENCRYPTED),
        );
        let bytes = header.to_wire();
        assert_eq!(
            bytes.len(),
            PacketHeader::SIZE,
            "the serialised header (= AEAD AAD) must be exactly 47 bytes"
        );
        // version-first, big-endian: the pinned version is the leading byte.
        assert_eq!(bytes[0], WIRE_VERSION);
        assert_eq!(PacketHeader::from_wire(&bytes).expect("roundtrip"), header);
    }

    #[test]
    fn test_phantom_packet_ack() {
        let session_id = SessionId::random();
        let ack = PhantomPacket::ack(session_id, 5, 100);

        assert!(ack.header.flags.is_ack());
        assert_eq!(ack.header.stream_id, 5);
        assert_eq!(ack.header.packet_number, 100);
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

        let bytes = packet.to_wire();
        let decoded = PhantomPacket::from_wire(&bytes).expect("roundtrip");
        assert_eq!(decoded, packet);
        assert_eq!(decoded.header.version, WIRE_VERSION);
        assert_eq!(decoded.header.stream_id, 7);
        assert_eq!(decoded.header.packet_number, 42);
        assert_eq!(decoded.header.epoch, 3);
        assert_eq!(decoded.header.path_id, 1);
        assert!(decoded.header.flags.is_reliable());
        assert!(decoded.header.flags.contains(PacketFlags::ENCRYPTED));
        assert_eq!(decoded.payload, vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }

    /// WIRE_VERSION 4 (T4.6) reorders the header so the 14 HP-protected bytes
    /// are contiguous at wire offset `[33..47]` — `packet_number(8) ‖ flags(2) ‖
    /// stream_id(2) ‖ epoch(1) ‖ path_id(1)` — after the cleartext `version(1) ‖
    /// session_id(32)` routing prefix that stays in the clear for the demux.
    #[test]
    fn v4_header_layout_offsets() {
        let header = PacketHeader::new(
            SessionId::from_bytes([0u8; 32]),
            0x1122,             // stream_id
            0x33445566778899AA, // packet_number
            PacketFlags::new(0xBCCD),
        )
        .with_epoch(0xEE)
        .with_path_id(0xFF);
        let b = header.to_wire();
        assert_eq!(b[0], WIRE_VERSION, "version @ 0 (cleartext)");
        assert_eq!(&b[1..33], &[0u8; 32], "session_id @ [1..33] (cleartext)");
        assert_eq!(
            &b[33..41],
            &0x33445566778899AAu64.to_be_bytes(),
            "packet_number @ [33..41]"
        );
        assert_eq!(&b[41..43], &0xBCCDu16.to_be_bytes(), "flags @ [41..43]");
        assert_eq!(&b[43..45], &0x1122u16.to_be_bytes(), "stream_id @ [43..45]");
        assert_eq!(b[45], 0xEE, "epoch @ 45");
        assert_eq!(b[46], 0xFF, "path_id @ 46");
        // Round-trips back to the same struct under the new layout.
        assert_eq!(PacketHeader::from_wire(&b).expect("roundtrip"), header);
    }

    /// T4.6 codec: `to_wire_masked` → `RawPacket::from_wire` → `unmask_header`
    /// recovers the original header for an arbitrary fixed mask, the masked wire
    /// region differs from the cleartext header (pn/flags hidden), and the
    /// routing prefix (version + session_id) stays readable without the mask.
    #[test]
    fn raw_packet_mask_unmask_round_trip() {
        let sid = SessionId::from_bytes([0x5Au8; 32]);
        let header = PacketHeader::new(
            sid,
            0x0203,             // stream_id
            0x1111222233334444, // packet_number
            PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::PRIORITY),
        )
        .with_epoch(7)
        .with_path_id(9);
        let packet = PhantomPacket::new(header, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]);
        // Arbitrary fixed 16-byte mask (production: HeaderProtector::mask_send).
        let mask: [u8; 16] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x01,
        ];

        let wire = packet.to_wire_masked(&mask);
        let cleartext = packet.to_wire();

        // The masked region on the wire hides the cleartext header bytes...
        assert_ne!(
            &wire[HP_PROTECTED_OFFSET..PacketHeader::SIZE],
            &cleartext[HP_PROTECTED_OFFSET..PacketHeader::SIZE],
            "pn/flags/stream_id/epoch/path_id must be masked on the wire"
        );
        // ...while the cleartext routing prefix is untouched.
        assert_eq!(
            &wire[..HP_PROTECTED_OFFSET],
            &cleartext[..HP_PROTECTED_OFFSET]
        );

        // The envelope parses without the mask (routing fields readable).
        let raw = RawPacket::from_wire(&wire).expect("raw parse");
        assert_eq!(raw.version, WIRE_VERSION);
        assert_eq!(raw.session_id, sid);
        assert_eq!(raw.payload, packet.payload);

        // Unmasking with the same mask recovers the exact header...
        let recovered = raw.unmask_header(&mask).expect("unmask");
        assert_eq!(recovered, header);
        // ...and the reassembled packet equals the original.
        assert_eq!(raw.into_packet(recovered), packet);
    }

    /// A too-short HP mask is rejected as a typed error, never a panic (the
    /// session always supplies a full 16-byte mask — this is defensive).
    #[test]
    fn unmask_header_rejects_short_mask() {
        let wire = PhantomPacket::new(
            PacketHeader::new(
                SessionId::from_bytes([1u8; 32]),
                1,
                1,
                PacketFlags::new(PacketFlags::ENCRYPTED),
            ),
            vec![0u8; 16],
        )
        .to_wire_masked(&[0u8; 16]);
        let raw = RawPacket::from_wire(&wire).expect("raw parse");
        assert!(
            raw.unmask_header(&[0u8; 8]).is_err(),
            "a mask shorter than HP_PROTECTED_LEN must error, not panic"
        );
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

        let bytes = packet.to_wire();
        let deser = PhantomPacket::from_wire(&bytes).expect("deserialize failed");
        assert_eq!(
            deser.extensions,
            vec![0xFF, 0x01, 0x00, 0x04, b't', b'e', b's', b't']
        );
    }
}
