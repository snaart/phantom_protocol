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
        if getrandom::fill(&mut bytes).is_err() {
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
/// negotiated (pre-1.0, no users); a decoder rejects anything else. `6` is the
/// anti-fingerprint diet: the version byte is now itself HP-masked (the WHOLE
/// 15-byte header `[0..15]` is masked — no constant cleartext byte), and the two
/// cleartext `u32` length prefixes are dropped (`payload` is the message
/// remainder — `recv_bytes` is message-framed — and `extensions` leave the wire),
/// saving 8 bytes/packet. `5` (ε) collapsed the two connection identifiers into
/// one rotating CID: the 32-byte inner `session_id` left the data-plane wire (it
/// stays in the AEAD AAD, reconstructed from session context), shrinking the
/// header to 15 bytes. `4` (T4.6) added QUIC-style header protection (RFC 9001
/// §5.4) over a 47-byte header; `3` (Phase 4) widened the packet number to `u64`.
/// See PROTOCOL.md § 4.2.
pub const WIRE_VERSION: u8 = 6;

/// Wire offset where the header-protected region begins. **WIRE v6
/// (anti-fingerprint): `0`** — the masked region now covers the WHOLE 15-byte
/// header, INCLUDING the `version(1)` byte, so the data-plane wire has no
/// constant cleartext byte to fingerprint. (Was `1` in v5, after the cleartext
/// version byte; `33` in v4, after `version ‖ session_id`.) Everything at
/// `[HP_PROTECTED_OFFSET..PacketHeader::SIZE]` is XOR-masked on the wire.
pub const HP_PROTECTED_OFFSET: usize = 0;

/// Length of the header-protected region (`PacketHeader::SIZE - HP_PROTECTED_OFFSET`
/// = 15 bytes in v6: `version ‖ packet_number ‖ flags ‖ stream_id ‖ epoch ‖
/// path_id`). The [`HeaderProtector`] produces a full 16-byte mask block; the
/// first `HP_PROTECTED_LEN` bytes are used.
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
    /// traffic-secret rekey chain (`HKDF-Expand(current, "phantom-rekey-v1", 32)`,
    /// Invariant 5) before decrypting this packet (Phase 1.5).
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
    /// Idle keep-alive PING (Direction #3 — download-only liveness). A small
    /// `ENCRYPTED | KEEPALIVE` packet with an **empty** payload that an idle
    /// sender emits to (a) refresh the peer's inbound-activity timer and (b)
    /// anchor its own liveness timer (the in-flight keep-alive lets a
    /// download-only path — which otherwise sends only ACKs and has nothing in
    /// flight — detect a silently-dead downstream). A bare `KEEPALIVE` is a
    /// PING; `KEEPALIVE | ACK` is the peer's PONG echo. Neither carries
    /// application bytes, so neither reaches `recv()`. (Spare flag bit — no
    /// header layout / `WIRE_VERSION` change.)
    pub const KEEPALIVE: u16 = 0x1000;
    /// Anti-fingerprint size padding present (WIRE v6, deliverable (c)). When set,
    /// the AEAD **plaintext** ends with a trailer `‹pad_n zero bytes› ‖ pad_n:u16be`
    /// that the receiver strips after decrypt (see [`crate::transport::shaping`]).
    /// The flag rides inside the HP-masked header, so it is invisible on the wire;
    /// the padding itself is encrypted + authenticated, so only the bucketed
    /// datagram size is observable. (Spare flag bit — no header layout change.)
    pub const PADDED: u16 = 0x2000;
    /// Anti-fingerprint cover (dummy) traffic (WIRE v6, deliverable (e)). An
    /// `ENCRYPTED | COVER` packet carries **no application data** (empty inner
    /// plaintext, typically `PADDED` to a bucket); its sole purpose is to normalize
    /// the outbound traffic pattern (idle-fill + a floor packet rate) so silence and
    /// volume no longer leak. It AEAD-authenticates like any packet (so it refreshes
    /// the peer's liveness and cannot be off-path injected); the receiver drops it
    /// before the data path, so it never reaches `recv()`. (Spare flag bit — no
    /// header layout / `WIRE_VERSION` change.)
    pub const COVER: u16 = 0x4000;
    // 0x8000 — reserved for future amendments.

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

/// Packet header — 15 bytes on the wire ([`PacketHeader::SIZE`]); the AEAD AAD is
/// the separate, larger 47-byte image ([`PacketHeader::AAD_SIZE`]).
///
/// Serialised by [`PacketHeader::to_wire`] as an explicit, fixed **big-endian**
/// (network byte order) image, `version` first (no serialization library). The
/// WIRE v6 (anti-fingerprint) wire layout is a contiguous 15-byte span, the WHOLE
/// of which is HP-masked on the wire (`HP_PROTECTED_OFFSET = 0` — no constant
/// cleartext byte). The 32-byte `session_id` is **off-wire**: it is a struct field
/// bound into the AEAD AAD but never transmitted (dropped from the wire in v5 / the
/// ε CID collapse), reconstructed by the receiver from session context.
///
/// ```text
/// off  0  version        u8       (= WIRE_VERSION = 6)            HP-MASKED ┐
/// off  1  packet_number  u64 be   (① per-direction monotonic)    HP-MASKED │
/// off  9  flags          u16 be                                  HP-MASKED │ [0..15]
/// off 11  stream_id      u16 be                                  HP-MASKED │
/// off 13  epoch          u8                                      HP-MASKED │
/// off 14  path_id        u8                                      HP-MASKED ┘
/// ```
///
/// The 47-byte AEAD AAD image ([`Self::to_aad_image`]) is the cleartext header
/// reconstructed off-wire (it additionally binds the off-wire `session_id`), so
/// flipping any authenticated byte (`version` / `session_id` included) fails
/// decryption. On the wire the whole `[0..15]` span is XOR-masked by the
/// per-session [`HeaderProtector`] (a wire mutation of the masked region unmasks to
/// a wrong header → wrong AAD → AEAD fails — no new oracle); the recv path
/// reconstructs the cleartext header via [`RawPacket::unmask_header`] before
/// computing the AAD. `epoch`/`stream_id`/`path_id` are authenticated in the AAD
/// but NOT in the nonce (which is `prefix‖packet_number`). The recv path also drops
/// a frame whose `version != WIRE_VERSION`. Frozen by
/// `core/tests/wire_vectors/packet_header.bin`; grammar in
/// `docs/protocol/PROTOCOL.md` § 4.2.
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
    /// Connection-migration path identifier (Phase 4.2). 0 = the implicit,
    /// always-validated handshake path; bumped per `migrate()` so the peer
    /// challenges the new path.
    pub path_id: u8,
}

impl PacketHeader {
    /// On-wire header size in bytes (ε / WIRE v5: `version(1)` + the 14 HP-masked
    /// fields; `session_id` is off-wire). The AEAD AAD is the larger
    /// [`Self::AAD_SIZE`] image (which still binds `session_id`).
    pub const SIZE: usize = 15;

    /// Size of the AEAD AAD header image: the byte-identical 47-byte v4 logical
    /// header (`version ‖ session_id ‖ packet_number ‖ flags ‖ stream_id ‖ epoch
    /// ‖ path_id`), reconstructed off-wire by [`Self::to_aad_image`]. Kept at 47
    /// so the v4 AEAD security argument carries over unchanged (design §2.2).
    pub const AAD_SIZE: usize = 47;

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

    /// Set the path id — stamped by the connection-migration path machinery
    /// (Phase 4.2; 0 = the implicit handshake path).
    pub fn with_path_id(mut self, path_id: u8) -> Self {
        self.path_id = path_id;
        self
    }

    /// Serialise to the fixed 15 on-wire bytes (big-endian, `version` first;
    /// ε / WIRE v5). `session_id` is **not** emitted — it is off-wire and lives
    /// only in the AEAD AAD ([`Self::to_aad_image`]) and the session context.
    pub fn to_wire(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0] = self.version;
        // Field layout after the version byte: packet_number ‖ flags ‖ stream_id ‖
        // epoch ‖ path_id (see the struct doc grammar). This is the CLEARTEXT image;
        // the WIRE v6 whole-header HP mask is applied separately by `to_wire_masked`.
        b[1..9].copy_from_slice(&self.packet_number.to_be_bytes());
        b[9..11].copy_from_slice(&self.flags.0.to_be_bytes());
        b[11..13].copy_from_slice(&self.stream_id.to_be_bytes());
        b[13] = self.epoch;
        b[14] = self.path_id;
        b
    }

    /// The AEAD AAD image: the byte-identical 47-byte v4 logical header
    /// (`version ‖ session_id ‖ packet_number ‖ flags ‖ stream_id ‖ epoch ‖
    /// path_id`). `session_id` is off-wire, so the data plane reconstructs it
    /// from the session context ([`Session::id`]) into `self.session_id` before
    /// computing the AAD; this keeps the AEAD binding (and its security
    /// argument) byte-identical to v4 (design §2.2).
    ///
    /// [`Session::id`]: crate::transport::session::Session::id
    pub fn to_aad_image(&self) -> [u8; Self::AAD_SIZE] {
        let mut b = [0u8; Self::AAD_SIZE];
        b[0] = self.version;
        b[1..33].copy_from_slice(&self.session_id.0);
        b[33..41].copy_from_slice(&self.packet_number.to_be_bytes());
        b[41..43].copy_from_slice(&self.flags.0.to_be_bytes());
        b[43..45].copy_from_slice(&self.stream_id.to_be_bytes());
        b[45] = self.epoch;
        b[46] = self.path_id;
        b
    }

    /// Parse a header from the first [`Self::SIZE`] (= 15) bytes of `bytes`. Does
    /// not validate `version` — the recv path gates on it separately. `session_id`
    /// is off-wire (ε / WIRE v5): it is left the placeholder zero here and set by
    /// [`Session::parse_protected`] from the routed session context.
    ///
    /// [`Session::parse_protected`]: crate::transport::session::Session::parse_protected
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < Self::SIZE {
            return Err(WireError::Truncated);
        }
        Ok(Self {
            version: bytes[0],
            // Off-wire placeholder; reconstructed by Session::parse_protected.
            session_id: SessionId([0u8; 32]),
            // Field layout after the version byte: packet_number ‖ flags ‖
            // stream_id ‖ epoch ‖ path_id (the inverse of `to_wire`).
            packet_number: u64::from_be_bytes([
                bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
            ]),
            flags: PacketFlags(u16::from_be_bytes([bytes[9], bytes[10]])),
            stream_id: u16::from_be_bytes([bytes[11], bytes[12]]),
            epoch: bytes[13],
            path_id: bytes[14],
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

/// Full packet with header and payload — the single on-wire data packet.
#[derive(Clone, PartialEq, Eq)]
pub struct PhantomPacket {
    /// Packet header (15 bytes on the wire; see [`PacketHeader::SIZE`])
    pub header: PacketHeader,
    /// Encrypted payload (or coalesced bundle if `COALESCED` flag set)
    pub payload: Vec<u8>,
    /// Forward-compat TLV headroom — retained for the AEAD-AAD/codec shape but
    /// **NOT serialised onto the WIRE v6 data-plane wire**: `to_wire` emits only
    /// `header ‖ payload`, and `from_wire` always yields an empty `Vec` here (see
    /// [`PhantomPacket::to_wire`]). Was a length-prefixed wire field pre-v6.
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

    /// Total wire size: the 15-byte header plus the payload (WIRE v6 — no length
    /// prefixes, no `extensions` on the wire).
    pub fn wire_size(&self) -> usize {
        PacketHeader::SIZE + self.payload.len()
    }

    /// Serialise to the on-wire bytes: `header(15) || payload`.
    ///
    /// **WIRE v6 (anti-fingerprint diet):** the two cleartext `u32` length
    /// prefixes (`payload_len` / `ext_len`) are GONE — `payload` is simply the
    /// message remainder after the 15-byte header. `SessionTransport::recv_bytes`
    /// is message-framed on every transport (UDP datagram / TCP 4-byte frame /
    /// embedded frame), so the prefixes were pure redundancy *and* a verifiable
    /// structural fingerprint (`ext_len == 0`, `payload_len == datagram − const`).
    /// `extensions` is no longer carried on the data-plane wire (it was always
    /// empty; the AEAD AAD still binds an empty extensions slice).
    ///
    /// This is the **cleartext** wire image (the 15-byte header still has
    /// `session_id` off-wire — the AEAD AAD is the separate 47-byte
    /// [`PacketHeader::to_aad_image`]). The data plane never puts these bytes on
    /// the wire directly — it calls [`Self::to_wire_masked`] to apply header
    /// protection (which now masks the whole 15-byte header, version included).
    pub fn to_wire(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.wire_size());
        b.extend_from_slice(&self.header.to_wire());
        b.extend_from_slice(&self.payload);
        b
    }

    /// Serialise with header protection applied: identical to [`Self::to_wire`],
    /// then the **whole** `[HP_PROTECTED_OFFSET..PacketHeader::SIZE]` region (WIRE
    /// v6: the 15 bytes `version ‖ packet_number ‖ flags ‖ stream_id ‖ epoch ‖
    /// path_id`) is XOR-masked with the caller-supplied HP `mask`. The mask is
    /// computed from this packet's `payload` ciphertext by the session's
    /// `HeaderProtector` (`mask_send`); the `payload` itself stays cleartext on the
    /// wire (it *is* the AEAD ciphertext) so the recv path can locate the sample —
    /// at the fixed offset [`PacketHeader::SIZE`] — before unmasking (the demux
    /// routes on the outer ConnId). With the version byte now masked too, the
    /// data-plane wire has no constant cleartext byte. Only the first
    /// [`HP_PROTECTED_LEN`] bytes of `mask` are used; a shorter `mask` masks fewer
    /// bytes rather than panicking (the session always supplies a full 16-byte
    /// mask).
    pub fn to_wire_masked(&self, mask: &[u8]) -> Vec<u8> {
        let mut buf = self.to_wire();
        // zip stops at the shorter of the 15-byte region and `mask`, so a short
        // mask masks fewer bytes rather than panicking.
        for (b, m) in buf[HP_PROTECTED_OFFSET..PacketHeader::SIZE]
            .iter_mut()
            .zip(mask)
        {
            *b ^= *m;
        }
        buf
    }

    /// Parse a packet from its on-wire bytes — the inverse of [`Self::to_wire`]
    /// (WIRE v6): the 15-byte header, then `payload` is the whole remainder. A
    /// buffer shorter than the header yields [`WireError::Truncated`]. `extensions`
    /// is always empty (off the v6 data-plane wire).
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let header = PacketHeader::from_wire(bytes)?;
        let payload = bytes[PacketHeader::SIZE..].to_vec();
        Ok(Self {
            header,
            payload,
            extensions: Vec::new(),
        })
    }
}

/// A partially-decoded v6 packet: the cleartext envelope with the **entire**
/// 15-byte header-protected region (version included) left **opaque**, plus the
/// `payload` (the message remainder). The recv path produces this from the raw
/// wire bytes *before* it has the per-session HP key — it locates the ciphertext
/// sample (`payload`, at the fixed offset 15) and calls
/// [`RawPacket::unmask_header`] with the mask computed from `payload` to recover
/// the [`PacketHeader`] (including its `version` byte; the off-wire `session_id`
/// is then set by [`Session::parse_protected`]). This is the codec half of header
/// protection; the mask itself is computed by the session's `HeaderProtector`
/// (this module stays crypto-free). Routing is by the outer (rotating) ConnId.
///
/// WIRE v6: no cleartext `version` byte and no length prefixes — the version is
/// inside `masked_header`, and `payload` is everything after the 15-byte header.
///
/// [`Session::parse_protected`]: crate::transport::session::Session::parse_protected
#[derive(Clone, Debug)]
pub struct RawPacket {
    /// The still-masked header-protected region (the WHOLE wire `[0..15]`,
    /// version included).
    masked_header: [u8; HP_PROTECTED_LEN],
    /// AEAD ciphertext = the message remainder after the 15-byte header (cleartext
    /// on the wire; the payload itself is the AEAD ciphertext).
    pub payload: Vec<u8>,
    /// Forward-compat headroom — always empty on the v6 data-plane wire (retained
    /// for the AAD/codec shape; see [`PhantomPacket::to_wire`]).
    pub extensions: Vec<u8>,
}

impl RawPacket {
    /// Parse the cleartext envelope of a v6 wire packet, leaving the whole 15-byte
    /// HP-masked header region opaque and taking `payload` as the remainder.
    /// Bounds-checked exactly like [`PhantomPacket::from_wire`] — a short / hostile
    /// buffer yields [`WireError::Truncated`], never a panic.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < PacketHeader::SIZE {
            return Err(WireError::Truncated);
        }
        let mut masked_header = [0u8; HP_PROTECTED_LEN];
        masked_header.copy_from_slice(&bytes[HP_PROTECTED_OFFSET..PacketHeader::SIZE]);
        let payload = bytes[PacketHeader::SIZE..].to_vec();
        Ok(Self {
            masked_header,
            payload,
            extensions: Vec::new(),
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
        // WIRE v6: the masked region is the whole 15-byte header (offset 0), so the
        // version byte is recovered here too — there is no cleartext prefix to copy.
        let mut hdr = [0u8; PacketHeader::SIZE];
        hdr[HP_PROTECTED_OFFSET..].copy_from_slice(&self.masked_header);
        for (h, m) in hdr[HP_PROTECTED_OFFSET..].iter_mut().zip(mask) {
            *h ^= *m;
        }
        // `session_id` is off-wire — PacketHeader::from_wire leaves it the
        // placeholder zero; Session::parse_protected sets it from self.id(). The
        // recovered `version` (hdr[0]) is checked by the recv path.
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

/// Legacy control-message enum for session management. NOTE: this is **not** the
/// live handshake / control wire format — the real handshake uses the borsh structs
/// in `transport::handshake` (`ClientHello` / `ServerHello` / …) and post-handshake
/// control rides in `PacketFlags` (`REKEY` / `PATH_VALIDATION` / `KEEPALIVE` / …).
/// This enum is currently unreferenced; retained as a definitional placeholder.
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

/// Transport-leg discriminant, retained as the **metric/telemetry label** axis in
/// `crate::observability` (the cardinality contract).
///
/// NOTE: this is *not* the live transport registry — the multipath `TransportLeg`
/// trait and the KCP / FakeTLS / native-TCP-*leg* legs it named were removed in the
/// PhantomUDP rewrite. `Kcp` and `FakeTls` survive only as stable label values so
/// the observability layer's instrument set is wire-format-stable; they are never
/// selected as a transport. The actual production transport is `Udp` (PhantomUDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum LegType {
    /// Retired KCP-over-UDP label (the KCP leg + `kcp-tokio` dep are gone). Kept as
    /// a stable telemetry label value only.
    Kcp,
    /// Raw TCP. The native multipath TCP *leg* was removed; `TcpSessionTransport`
    /// (a `SessionTransport`) is the current TCP byte-pipe.
    Tcp,
    /// Retired FakeTLS-over-TCP obfuscation label (the leg returned as the
    /// off-by-default `mimicry` transport). Kept as a stable telemetry label only.
    FakeTls,
    /// PhantomUDP — the native reliable transport over raw UDP (Phase 1); the
    /// production transport.
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

/// Scheduling strategy for the `Scheduler`. NOTE: the scheduler is **vestigial** —
/// the project does single-path connection migration, not multipath aggregation, so
/// `select_paths` is never called on the live data path. This enum is constructed
/// (defaulting to `LowLatency`) and threaded through `Session`/config but does not
/// steer production traffic.
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
        assert_eq!(PacketFlags::KEEPALIVE, 0x1000);
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
    fn packet_header_serializes_to_15_bytes() {
        assert_eq!(PacketHeader::SIZE, 15);
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
            "the v5 on-wire header is exactly 15 bytes (session_id is off-wire)"
        );
        // version-first, big-endian: the pinned version is the leading byte.
        assert_eq!(bytes[0], WIRE_VERSION);
        // session_id (zero here) round-trips as the off-wire placeholder.
        assert_eq!(PacketHeader::from_wire(&bytes).expect("roundtrip"), header);
    }

    /// v5 (ε) drops `session_id` from the 15-byte wire image, but the AEAD AAD
    /// stays the **byte-identical 47-byte v4 image** — `version ‖ session_id ‖
    /// packet_number ‖ flags ‖ stream_id ‖ epoch ‖ path_id` — reconstructed
    /// off-wire. Pinning it keeps the v4 AEAD security argument unchanged
    /// (design §2.2): a masked-region tamper unmasks to a wrong header → wrong
    /// AAD → AEAD fail, with no new oracle.
    #[test]
    fn to_aad_image_is_the_47_byte_v4_layout() {
        let sid = SessionId::from_bytes([0x5Au8; 32]);
        let header = PacketHeader::new(sid, 0x1122, 0x33445566778899AA, PacketFlags::new(0xBCCD))
            .with_epoch(0xEE)
            .with_path_id(0xFF);
        let aad = header.to_aad_image();
        assert_eq!(
            aad.len(),
            47,
            "AAD image stays the 47-byte v4 logical header"
        );
        assert_eq!(aad[0], WIRE_VERSION, "version @ 0");
        assert_eq!(
            &aad[1..33],
            &[0x5Au8; 32],
            "session_id @ [1..33] (off-wire, in AAD)"
        );
        assert_eq!(
            &aad[33..41],
            &0x33445566778899AAu64.to_be_bytes(),
            "packet_number @ [33..41]"
        );
        assert_eq!(&aad[41..43], &0xBCCDu16.to_be_bytes(), "flags @ [41..43]");
        assert_eq!(
            &aad[43..45],
            &0x1122u16.to_be_bytes(),
            "stream_id @ [43..45]"
        );
        assert_eq!(aad[45], 0xEE, "epoch @ 45");
        assert_eq!(aad[46], 0xFF, "path_id @ 46");
    }

    /// The 15-byte wire image carries no `session_id`: a distinctive session_id
    /// never appears in `to_wire()` output (it lives only in the AAD + session
    /// context). This is the unlinkability-adjacent wire-diet property of ε.
    #[test]
    fn to_wire_omits_session_id() {
        let sid = SessionId::from_bytes([0xABu8; 32]);
        let header = PacketHeader::new(sid, 7, 42, PacketFlags::new(PacketFlags::ENCRYPTED));
        let wire = header.to_wire();
        assert_eq!(wire.len(), 15);
        assert!(
            !wire.windows(4).any(|w| w == [0xAB, 0xAB, 0xAB, 0xAB]),
            "session_id must not be serialised onto the v5 wire"
        );
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
        // session_id is off-wire in v5 — the codec leaves it the placeholder zero
        // (the session layer reconstructs it); every other field + the payload
        // round-trip exactly.
        assert_eq!(
            decoded.header.session_id,
            SessionId::from_bytes([0u8; 32]),
            "session_id is off-wire (reconstructed by Session::parse_protected)"
        );
        assert_eq!(decoded.header.version, WIRE_VERSION);
        assert_eq!(decoded.header.stream_id, 7);
        assert_eq!(decoded.header.packet_number, 42);
        assert_eq!(decoded.header.epoch, 3);
        assert_eq!(decoded.header.path_id, 1);
        assert!(decoded.header.flags.is_reliable());
        assert!(decoded.header.flags.contains(PacketFlags::ENCRYPTED));
        assert_eq!(decoded.payload, vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }

    /// WIRE v6 (anti-fingerprint diet): the data-plane packet drops BOTH cleartext
    /// `u32` length prefixes — `payload` is the message remainder after the 15-byte
    /// header (`SessionTransport::recv_bytes` is message-framed, so the prefixes
    /// were pure redundancy) — and carries no `extensions` on the wire. The version
    /// byte also joins the HP-masked region (`HP_PROTECTED_OFFSET == 0`), so nothing
    /// in the header is a constant cleartext fingerprint.
    #[test]
    fn v6_packet_drops_length_prefixes_and_masks_version() {
        // The masked region now starts at byte 0 (covers the version byte) and
        // spans the whole 15-byte header.
        assert_eq!(HP_PROTECTED_OFFSET, 0, "v6 masks from the version byte");
        assert_eq!(
            HP_PROTECTED_LEN,
            PacketHeader::SIZE,
            "v6 masks the whole 15-byte header"
        );
        assert_eq!(
            WIRE_VERSION, 6,
            "anti-fingerprint diet bumps the wire version"
        );

        let header = PacketHeader::new(
            SessionId::from_bytes([0u8; 32]),
            7,
            42,
            PacketFlags::new(PacketFlags::ENCRYPTED),
        );
        let payload = vec![0xCAu8; 40];
        let packet = PhantomPacket::new(header, payload.clone());
        let wire = packet.to_wire();
        // No 8 bytes of length prefixes: wire == header(15) ‖ payload.
        assert_eq!(
            wire.len(),
            PacketHeader::SIZE + payload.len(),
            "v6: header ‖ payload, no length prefixes"
        );
        assert_eq!(
            &wire[PacketHeader::SIZE..],
            &payload[..],
            "payload is the message remainder"
        );
        assert_eq!(
            packet.wire_size(),
            PacketHeader::SIZE + payload.len(),
            "wire_size() drops the 8 prefix bytes"
        );
        // Round-trips: payload is everything after the header; extensions are gone.
        let decoded = PhantomPacket::from_wire(&wire).expect("v6 roundtrip");
        assert_eq!(decoded.payload, payload);
        assert!(
            decoded.extensions.is_empty(),
            "extensions are off the v6 data-plane wire"
        );
    }

    /// WIRE v6 carries a contiguous masked `[0..15]` header — `version(1) ‖
    /// packet_number(8) ‖ flags(2) ‖ stream_id(2) ‖ epoch(1) ‖ path_id(1)` — after
    /// the outer (rotating) ConnId. The `PacketHeader::to_wire` image itself is
    /// unchanged from v5 (still version-first); the diet changes the *masking span*
    /// and the surrounding `PhantomPacket` framing.
    #[test]
    fn v6_header_layout_offsets() {
        let header = PacketHeader::new(
            SessionId::from_bytes([0x5Au8; 32]),
            0x1122,             // stream_id
            0x33445566778899AA, // packet_number
            PacketFlags::new(0xBCCD),
        )
        .with_epoch(0xEE)
        .with_path_id(0xFF);
        let b = header.to_wire();
        assert_eq!(b.len(), 15, "v5 wire header is 15 bytes");
        assert_eq!(b[0], WIRE_VERSION, "version @ 0 (cleartext)");
        assert_eq!(
            &b[1..9],
            &0x33445566778899AAu64.to_be_bytes(),
            "packet_number @ [1..9]"
        );
        assert_eq!(&b[9..11], &0xBCCDu16.to_be_bytes(), "flags @ [9..11]");
        assert_eq!(&b[11..13], &0x1122u16.to_be_bytes(), "stream_id @ [11..13]");
        assert_eq!(b[13], 0xEE, "epoch @ 13");
        assert_eq!(b[14], 0xFF, "path_id @ 14");
        // Round-trips the 14 masked fields; session_id is off-wire (placeholder).
        let rt = PacketHeader::from_wire(&b).expect("roundtrip");
        assert_eq!(rt.packet_number, header.packet_number);
        assert_eq!(rt.flags, header.flags);
        assert_eq!(rt.stream_id, header.stream_id);
        assert_eq!(rt.epoch, header.epoch);
        assert_eq!(rt.path_id, header.path_id);
        assert_eq!(
            rt.session_id,
            SessionId::from_bytes([0u8; 32]),
            "session_id off-wire (reconstructed from session context)"
        );
    }

    /// T4.6 codec at the v5 layout: `to_wire_masked` → `RawPacket::from_wire` →
    /// `unmask_header` recovers the 14 masked fields for an arbitrary fixed mask,
    /// the masked wire region differs from the cleartext header (pn/flags
    /// hidden), and only the cleartext `version` byte stays readable without the
    /// mask (session_id is off-wire — reconstructed by `Session::parse_protected`).
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

        // WIRE v6: the masked region is the WHOLE 15-byte header [0..15] — every
        // header byte, version INCLUDED, differs from the cleartext on the wire.
        assert_ne!(
            &wire[HP_PROTECTED_OFFSET..PacketHeader::SIZE],
            &cleartext[HP_PROTECTED_OFFSET..PacketHeader::SIZE],
            "version/pn/flags/stream_id/epoch/path_id must all be masked on the wire"
        );
        assert_eq!(
            HP_PROTECTED_OFFSET, 0,
            "v6 masks from byte 0 (version included)"
        );
        assert_ne!(
            wire[0], cleartext[0],
            "the version byte is masked in v6 (no constant cleartext byte)"
        );

        // The envelope parses without the mask (payload located at the fixed
        // offset 15; the version is inside the masked region, not cleartext).
        let raw = RawPacket::from_wire(&wire).expect("raw parse");
        assert_eq!(raw.payload, packet.payload);

        // Unmasking recovers all 15 masked fields incl. version; session_id stays
        // off-wire (the session layer sets it from `self.id()`), so compare field-wise.
        let recovered = raw.unmask_header(&mask).expect("unmask");
        assert_eq!(
            recovered.version, WIRE_VERSION,
            "the masked version byte round-trips through unmask"
        );
        assert_eq!(recovered.packet_number, header.packet_number);
        assert_eq!(recovered.flags, header.flags);
        assert_eq!(recovered.stream_id, header.stream_id);
        assert_eq!(recovered.epoch, header.epoch);
        assert_eq!(recovered.path_id, header.path_id);
        assert_eq!(
            recovered.session_id,
            SessionId::from_bytes([0u8; 32]),
            "session_id off-wire after unmask"
        );
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

    /// WIRE v6 drops `extensions` from the data-plane wire (D3): the field was
    /// always empty in practice and the AEAD AAD still binds an empty slice.
    /// `to_wire` emits only `header ‖ payload`; any `extensions` set on the struct
    /// are NOT serialised, and `from_wire` always yields empty extensions. (The
    /// forward-compat headroom can return later via a reserved flag + an encrypted
    /// TLV inside the padded plaintext — see the v6 anti-fingerprint design.)
    #[test]
    fn extensions_are_dropped_from_the_v6_wire() {
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
        // The wire is exactly header ‖ payload — the extensions bytes are absent.
        assert_eq!(bytes.len(), PacketHeader::SIZE + 3, "header ‖ payload only");
        let deser = PhantomPacket::from_wire(&bytes).expect("deserialize failed");
        assert_eq!(deser.payload, vec![1, 2, 3]);
        assert!(
            deser.extensions.is_empty(),
            "extensions are off the v6 data-plane wire"
        );
    }
}
