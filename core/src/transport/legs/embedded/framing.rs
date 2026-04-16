//! Length-prefix framing for `EmbeddedLeg`.
//!
//! `embedded-io-async` is a byte stream; `SessionTransport` is message-
//! oriented. Each frame is `[len: u32 BE][payload]` — byte-identical to
//! `TcpSessionTransport`'s framing, so an embedded client and a TCP server
//! interoperate at this layer. Pure: no I/O and no state — the leg drives the
//! actual reads and writes and owns the buffer.

/// Width of the big-endian length prefix prepended to every frame.
pub const HEADER_LEN: usize = 4;

/// Errors from length-prefix framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// A frame length — declared on the wire, or requested for send — exceeds
    /// the fixed buffer capacity it has to fit in.
    FrameTooLarge {
        /// The offending frame length, in bytes.
        len: usize,
        /// The buffer capacity it overran, in bytes.
        capacity: usize,
    },
}

/// Encode the big-endian length prefix for an outbound frame of `payload_len`
/// bytes, validating it fits a receiver buffer of `capacity` bytes.
pub fn encode_header(
    payload_len: usize,
    capacity: usize,
) -> Result<[u8; HEADER_LEN], FramingError> {
    if payload_len > capacity {
        return Err(FramingError::FrameTooLarge {
            len: payload_len,
            capacity,
        });
    }
    match u32::try_from(payload_len) {
        Ok(len) => Ok(len.to_be_bytes()),
        Err(_) => Err(FramingError::FrameTooLarge {
            len: payload_len,
            capacity,
        }),
    }
}

/// Decode a big-endian length prefix, validating the frame it announces fits
/// a receiver buffer of `capacity` bytes.
pub fn decode_header(header: &[u8; HEADER_LEN], capacity: usize) -> Result<usize, FramingError> {
    let len = u32::from_be_bytes(*header) as usize;
    if len > capacity {
        return Err(FramingError::FrameTooLarge { len, capacity });
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_header_writes_big_endian_length() {
        let header = encode_header(0x0102_0304, 0x1000_0000).expect("within capacity");
        assert_eq!(header, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn encode_header_rejects_length_over_capacity() {
        let err = encode_header(2000, 1024).expect_err("2000 > 1024 capacity");
        assert_eq!(
            err,
            FramingError::FrameTooLarge {
                len: 2000,
                capacity: 1024
            }
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn encode_header_rejects_length_over_u32_max() {
        // The 4-byte wire prefix cannot express a length past u32::MAX, even
        // if the receiver buffer notionally could. Only reachable on 64-bit
        // hosts; on 32-bit targets `usize` already caps at u32::MAX.
        let huge = u32::MAX as usize + 1;
        let err = encode_header(huge, usize::MAX).expect_err("over u32::MAX wire limit");
        assert_eq!(
            err,
            FramingError::FrameTooLarge {
                len: huge,
                capacity: usize::MAX
            }
        );
    }

    #[test]
    fn encode_decode_round_trips() {
        let capacity = 0x1000_0000;
        for len in [0_usize, 1, 255, 0x0102_0304] {
            let header = encode_header(len, capacity).expect("within capacity");
            let decoded = decode_header(&header, capacity).expect("within capacity");
            assert_eq!(decoded, len, "round-trip failed for len {len}");
        }
    }

    #[test]
    fn decode_header_rejects_length_over_capacity() {
        // 0x0000_0800 = 2048; the receiver buffer is only 1024 bytes.
        let err = decode_header(&[0x00, 0x00, 0x08, 0x00], 1024).expect_err("2048 > 1024 capacity");
        assert_eq!(
            err,
            FramingError::FrameTooLarge {
                len: 2048,
                capacity: 1024
            }
        );
    }
}
