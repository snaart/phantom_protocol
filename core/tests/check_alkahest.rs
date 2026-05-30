use phantom_core::transport::types::*;

#[test]
fn test_header_size() {
    let header = PacketHeader::new(SessionId([0; 32]), 1, 2, PacketFlags::new(0));

    let mut buf = Vec::new();
    let (size, _) = alkahest::serialize_to_vec::<PacketHeader, _>(&header, &mut buf);

    // The serialized header is the AEAD AAD; pin it to the frozen 45-byte layout.
    assert_eq!(
        size,
        PacketHeader::SIZE,
        "serialized header must equal PacketHeader::SIZE"
    );
    assert_eq!(
        size, 45,
        "the unified packet header is 45 bytes on the wire"
    );
}
