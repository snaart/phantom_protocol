//! Map a logical frame to one or more UDP datagrams (and back), fragmenting frames larger
//! than the path MTU. Reuses `FragmentAssembler` (with its anti-DoS bounds) by zero-padding the
//! 8-byte `cid` to the assembler's `[u8;16]` key.

use crate::transport::fragmentation::{CryptoFrame, MAX_TOTAL_CHUNKS};
use crate::transport::phantom_udp::envelope::{
    decode_header, encode_header, EnvelopeError, OuterHeader, PacketType, CID_LEN, FRAG_SUBHDR_LEN,
    MAX_INNER_FRAG_CHUNK, MAX_INNER_UNFRAGMENTED, PATH_MTU,
};

/// Re-export so callers (transports, demux) import one assembler type from here.
pub use crate::transport::fragmentation::FragmentAssembler;

fn cid16(cid: &[u8; CID_LEN]) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[..CID_LEN].copy_from_slice(cid);
    k
}

/// Encode one logical `frame` as one (or, if oversized, several) UDP datagrams.
/// `packet_id` disambiguates concurrently-fragmented frames from the same `cid`
/// (a monotonically increasing per-connection counter; ignored for unfragmented frames).
///
/// Returns `Err(EnvelopeError::FrameTooLarge)` when `frame` would require more than
/// `MAX_TOTAL_CHUNKS` fragments (i.e. exceeds roughly 253 KiB at the current `PATH_MTU`).
/// Such frames would be silently dropped by the receiver's `FragmentAssembler`, so
/// we surface the error here instead.
///
/// Note: `MAX_INNER_FRAG_CHUNK` must remain ≤ the assembler's accepted chunk size
/// (`MAX_UDP_PAYLOAD`, currently 1200 bytes) — a coupling to revisit if `PATH_MTU`
/// ever rises (e.g. via DPLPMTUD).
pub fn encode_datagrams(
    ty: PacketType,
    cid: &[u8; CID_LEN],
    packet_id: u32,
    frame: &[u8],
) -> Result<Vec<Vec<u8>>, EnvelopeError> {
    if frame.len() <= MAX_INNER_UNFRAGMENTED {
        let mut d = Vec::with_capacity(super::envelope::HDR_LEN + frame.len());
        encode_header(&mut d, ty, false, cid);
        d.extend_from_slice(frame);
        return Ok(vec![d]);
    }
    let chunks: Vec<&[u8]> = frame.chunks(MAX_INNER_FRAG_CHUNK).collect();
    if chunks.len() > MAX_TOTAL_CHUNKS as usize {
        return Err(EnvelopeError::FrameTooLarge);
    }
    let total = chunks.len() as u16;
    let mut out = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let mut d = Vec::with_capacity(PATH_MTU);
        encode_header(&mut d, ty, true, cid);
        d.extend_from_slice(&packet_id.to_be_bytes());
        d.extend_from_slice(&(i as u16).to_be_bytes());
        d.extend_from_slice(&total.to_be_bytes());
        d.extend_from_slice(chunk);
        out.push(d);
    }
    Ok(out)
}

/// Decode one datagram. Returns its header and, when the datagram completes a frame
/// (or is unfragmented), the reassembled frame. Fragments are fed to `asm`.
pub fn push_datagram(
    asm: &mut FragmentAssembler,
    datagram: &[u8],
) -> Result<(OuterHeader, Option<Vec<u8>>), EnvelopeError> {
    let (hdr, rest) = decode_header(datagram)?;
    if !hdr.fragmented {
        return Ok((hdr, Some(rest.to_vec())));
    }
    if rest.len() < FRAG_SUBHDR_LEN {
        return Err(EnvelopeError::Truncated);
    }
    let packet_id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    let chunk_index = u16::from_be_bytes([rest[4], rest[5]]);
    let total_chunks = u16::from_be_bytes([rest[6], rest[7]]);
    let payload = rest[FRAG_SUBHDR_LEN..].to_vec();
    let frame = CryptoFrame {
        session_id: cid16(&hdr.cid),
        packet_id,
        chunk_index,
        total_chunks,
        payload,
    };
    Ok((hdr, asm.process_chunk(frame)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::phantom_udp::envelope::{EnvelopeError, PacketType};

    #[test]
    fn unfragmented_single_datagram_roundtrip() {
        let cid = [7u8; 8];
        let frame = b"small handshake frame".to_vec();
        let dgrams = encode_datagrams(PacketType::Initial, &cid, 1, &frame).expect("encode");
        assert_eq!(dgrams.len(), 1, "small frame is one datagram");
        let mut asm = FragmentAssembler::new();
        let (hdr, out) = push_datagram(&mut asm, &dgrams[0]).expect("decode");
        assert_eq!(hdr.cid, cid);
        assert_eq!(out.as_deref(), Some(frame.as_slice()));
    }

    #[test]
    fn large_frame_fragments_and_reassembles() {
        let cid = [9u8; 8];
        let frame: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect(); // ~10 KB, like a ServerHello
        let dgrams = encode_datagrams(PacketType::Initial, &cid, 42, &frame).expect("encode");
        assert!(dgrams.len() > 1, "10 KB must fragment");
        for d in &dgrams {
            assert!(d.len() <= PATH_MTU, "no datagram may exceed the path MTU");
        }
        let mut asm = FragmentAssembler::new();
        let mut reassembled = None;
        for d in &dgrams {
            if let (_, Some(done)) = push_datagram(&mut asm, d).expect("decode") {
                reassembled = Some(done);
            }
        }
        assert_eq!(reassembled.as_deref(), Some(frame.as_slice()));
    }

    #[test]
    fn fragmentation_boundary() {
        let cid = [1u8; 8];
        // Exactly MAX_INNER_UNFRAGMENTED bytes => one datagram.
        let exact = vec![0u8; MAX_INNER_UNFRAGMENTED];
        assert_eq!(
            encode_datagrams(PacketType::Initial, &cid, 0, &exact)
                .expect("encode")
                .len(),
            1
        );
        // One more byte => exactly two chunks.
        let over = vec![0u8; MAX_INNER_UNFRAGMENTED + 1];
        assert_eq!(
            encode_datagrams(PacketType::Initial, &cid, 0, &over)
                .expect("encode")
                .len(),
            2
        );
    }

    #[test]
    fn truncated_fragment_returns_err() {
        // A fragmented datagram (F bit set) whose body is shorter than the 8-byte frag subheader.
        let cid = [2u8; 8];
        let mut d = Vec::new();
        crate::transport::phantom_udp::envelope::encode_header(
            &mut d,
            PacketType::Initial,
            true,
            &cid,
        );
        d.extend_from_slice(&[0u8; 4]); // only 4 trailing bytes < FRAG_SUBHDR_LEN
        let mut asm = FragmentAssembler::new();
        assert!(matches!(
            push_datagram(&mut asm, &d),
            Err(EnvelopeError::Truncated)
        ));
    }

    #[test]
    fn oversized_frame_returns_err() {
        let cid = [3u8; 8];
        // More than MAX_TOTAL_CHUNKS * MAX_INNER_FRAG_CHUNK bytes => too many chunks.
        let huge = vec![0u8; (super::MAX_TOTAL_CHUNKS as usize + 1) * MAX_INNER_FRAG_CHUNK];
        assert!(matches!(
            encode_datagrams(PacketType::Initial, &cid, 0, &huge),
            Err(EnvelopeError::FrameTooLarge)
        ));
    }
}
