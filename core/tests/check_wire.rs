use phantom_protocol::transport::types::*;

#[test]
fn test_header_size() {
    let header = PacketHeader::new(SessionId([0; 32]), 1, 2, PacketFlags::new(0));

    // The serialized wire header (ε / WIRE v5: session_id is off-wire); pin its
    // 15-byte size. The AEAD AAD is the separate 47-byte `to_aad_image()`.
    let bytes = header.to_wire();
    assert_eq!(
        bytes.len(),
        PacketHeader::SIZE,
        "serialized header must equal PacketHeader::SIZE"
    );
    assert_eq!(
        bytes.len(),
        15,
        "the v5 packet header is 15 bytes on the wire"
    );
    // version-first, big-endian, lossless round-trip.
    assert_eq!(bytes[0], WIRE_VERSION);
    assert_eq!(PacketHeader::from_wire(&bytes).expect("round-trip"), header);
}
