use phantom_protocol::transport::types::*;

#[test]
fn test_header_size() {
    let header = PacketHeader::new(SessionId([0; 32]), 1, 2, PacketFlags::new(0));

    // The serialized header is the AEAD AAD; pin it to the frozen 47-byte layout.
    let bytes = header.to_wire();
    assert_eq!(
        bytes.len(),
        PacketHeader::SIZE,
        "serialized header must equal PacketHeader::SIZE"
    );
    assert_eq!(
        bytes.len(),
        47,
        "the unified packet header is 47 bytes on the wire"
    );
    // version-first, big-endian, lossless round-trip.
    assert_eq!(bytes[0], WIRE_VERSION);
    assert_eq!(PacketHeader::from_wire(&bytes).expect("round-trip"), header);
}
