use phantom_core::transport::types::*;

#[test]
fn test_header_size() {
    let header = PacketHeader {
        session_id: SessionId([0; 32]),
        stream_id: 1,
        sequence: 2,
        flags: PacketFlags(0),
        ack_delay: 0,
    };
    
    let mut buf = Vec::new();
    let (size, _) = alkahest::serialize_to_vec::<PacketHeader, _>(&header, &mut buf);
    
    // PhantomPacket header should be compact
    assert!(size > 0, "Header size should be non-zero");
    assert!(size < 256, "Header should be compact, got {} bytes", size);
}
