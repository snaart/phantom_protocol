//! PhantomUDP outer datagram envelope — transport framing (NOT the frozen inner wire).
//! Every UDP datagram begins with `[flags: u8][cid: [u8;8]]`. Like `TcpSessionTransport`'s
//! 4-byte length prefix, this is outside `core/tests/wire_vectors` and does not bump
//! `WIRE_VERSION`/`PROTOCOL_VERSION`.

/// Connection-ID length (bytes). 8 = QUIC-parity, single-cache-line demux key.
pub const CID_LEN: usize = 8;
/// Connection ID: a client-chosen, lifetime-stable routing label. Unauthenticated —
/// security rests on the inner Phantom AEAD (Invariant 2/4). NEVER transcript-bound.
pub type ConnId = [u8; CID_LEN];

/// Outer header length: flags byte + cid.
pub const HDR_LEN: usize = 1 + CID_LEN;
/// Conservative path-MTU payload budget for Phase 1 (DPLPMTUD to raise it is Phase 5).
pub const PATH_MTU: usize = 1200;
/// Fragment subheader: packet_id u32be + chunk_index u16be + total_chunks u16be.
pub const FRAG_SUBHDR_LEN: usize = 8;
/// Largest inner frame that fits one unfragmented datagram.
pub const MAX_INNER_UNFRAGMENTED: usize = PATH_MTU - HDR_LEN;
/// Largest chunk payload per fragmented datagram.
pub const MAX_INNER_FRAG_CHUNK: usize = PATH_MTU - HDR_LEN - FRAG_SUBHDR_LEN;

const TYPE_SHIFT: u8 = 6;
const FRAG_BIT: u8 = 0b0010_0000;
const RESERVED_MASK: u8 = 0b0001_1111; // bits 4..0 must be 0 in Phase 1

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PacketType {
    /// Long header: inner = a borsh handshake message (ClientHello/ServerHello/HelloRetryRequest/ServerReject).
    Initial,
    /// Short header: inner = a `PhantomPacket` (45-byte header + body).
    OneRtt,
    /// Server -> client stateless address-validation token (reserved; unused in Phase 1).
    Retry,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OuterHeader {
    pub ty: PacketType,
    pub fragmented: bool,
    pub cid: ConnId,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvelopeError {
    Truncated,
    ReservedType,
    ReservedBitsSet,
    FrameTooLarge,
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "datagram too short for the PhantomUDP envelope header"),
            Self::ReservedType => write!(f, "reserved PhantomUDP packet type"),
            Self::ReservedBitsSet => write!(f, "reserved PhantomUDP flag bits set"),
            Self::FrameTooLarge => write!(f, "frame exceeds the maximum fragmentable size"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Append `[flags][cid]` to `buf`.
pub fn encode_header(buf: &mut Vec<u8>, ty: PacketType, fragmented: bool, cid: &ConnId) {
    let type_bits = match ty {
        PacketType::Initial => 0b00,
        PacketType::OneRtt => 0b01,
        PacketType::Retry => 0b10,
    };
    let mut flags = type_bits << TYPE_SHIFT;
    if fragmented {
        flags |= FRAG_BIT;
    }
    buf.push(flags);
    buf.extend_from_slice(cid);
}

/// Parse `[flags][cid]`; returns the header and the remaining bytes.
pub fn decode_header(buf: &[u8]) -> Result<(OuterHeader, &[u8]), EnvelopeError> {
    if buf.len() < HDR_LEN {
        return Err(EnvelopeError::Truncated);
    }
    let flags = buf[0];
    if flags & RESERVED_MASK != 0 {
        return Err(EnvelopeError::ReservedBitsSet);
    }
    let ty = match flags >> TYPE_SHIFT {
        0b00 => PacketType::Initial,
        0b01 => PacketType::OneRtt,
        0b10 => PacketType::Retry,
        _ => return Err(EnvelopeError::ReservedType),
    };
    let fragmented = flags & FRAG_BIT != 0;
    let mut cid = [0u8; CID_LEN];
    cid.copy_from_slice(&buf[1..1 + CID_LEN]);
    Ok((
        OuterHeader {
            ty,
            fragmented,
            cid,
        },
        &buf[HDR_LEN..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_initial_unfragmented() {
        let cid: ConnId = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut buf = Vec::new();
        encode_header(&mut buf, PacketType::Initial, false, &cid);
        assert_eq!(buf.len(), HDR_LEN);
        let (hdr, rest) = decode_header(&buf).expect("decode");
        assert_eq!(hdr.ty, PacketType::Initial);
        assert!(!hdr.fragmented);
        assert_eq!(hdr.cid, cid);
        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_onertt_fragmented_with_payload() {
        let cid: ConnId = [9; 8];
        let mut buf = Vec::new();
        encode_header(&mut buf, PacketType::OneRtt, true, &cid);
        buf.extend_from_slice(b"abc");
        let (hdr, rest) = decode_header(&buf).expect("decode");
        assert_eq!(hdr.ty, PacketType::OneRtt);
        assert!(hdr.fragmented);
        assert_eq!(rest, b"abc");
    }

    #[test]
    fn rejects_truncated() {
        assert!(matches!(
            decode_header(&[0u8; 4]),
            Err(EnvelopeError::Truncated)
        ));
    }

    #[test]
    fn rejects_reserved_type() {
        let mut buf = vec![0b1100_0000]; // type = 0b11 reserved
        buf.extend_from_slice(&[0u8; CID_LEN]);
        assert!(matches!(
            decode_header(&buf),
            Err(EnvelopeError::ReservedType)
        ));
    }

    #[test]
    fn rejects_reserved_bits_set() {
        let mut buf = vec![0b0000_0001]; // a reserved low bit set
        buf.extend_from_slice(&[0u8; CID_LEN]);
        assert!(matches!(
            decode_header(&buf),
            Err(EnvelopeError::ReservedBitsSet)
        ));
    }
}
