//! The testbed application protocol.
//!
//! Spoken **inside** an established, encrypted Phantom session — every frame
//! here has already been through the handshake, the AEAD, and header
//! protection by the time either side sees it.
//!
//! Deliberately trivial: one verb byte plus hand-rolled big-endian fields, no
//! serialization library. The point of keeping it this simple is that a bug
//! *here* must never be mistakable for a bug in the protocol under test.
//!
//! Message *delimitation* is not this module's job — see [`crate::framing`].
//! `PhantomSession::send()` splits payloads above 1300 B and the peer's
//! `recv()` yields the pieces separately, so a length prefix and explicit
//! reassembly sit between this codec and the session.
//!
//! Decoding is bounded and total: every field is length-checked before it is
//! read, so a truncated or hostile frame yields a typed `ProtoError` rather
//! than a panic or an attacker-sized allocation.

use std::fmt;

// ── Verbs ───────────────────────────────────────────────────────────────────

pub const VERB_ECHO: u8 = 0x01;
pub const VERB_SINK: u8 = 0x02;
pub const VERB_SINK_END: u8 = 0x03;
pub const VERB_SOURCE_REQ: u8 = 0x04;
pub const VERB_SOURCE_DATA: u8 = 0x05;
pub const VERB_SOURCE_END: u8 = 0x06;
pub const VERB_SINK_REPORT: u8 = 0x07;
pub const VERB_STATS_REQ: u8 = 0x08;
pub const VERB_STATS: u8 = 0x09;
pub const VERB_BYE: u8 = 0x0A;
pub const VERB_UPLOAD_BEGIN: u8 = 0x0B;
pub const VERB_UPLOAD_CHUNK: u8 = 0x0C;
pub const VERB_UPLOAD_END: u8 = 0x0D;
pub const VERB_MARK: u8 = 0x0E;
pub const VERB_ECHO_REPLY: u8 = 0x0F;

/// Upper bound on a single decoded frame body.
///
/// Sized under the `TcpSessionTransport` established-phase frame cap (4 MiB) so
/// the testbed can never be the layer that trips it. Scenario payloads stay far
/// below this; the cap exists so a corrupted length field fails loudly instead
/// of allocating.
pub const MAX_FRAME_BODY: usize = 2 * 1024 * 1024;

/// Chunk size for result-bundle upload. Comfortably under `MAX_FRAME_BODY` and
/// a reasonable unit of retransmission on a lossy path.
pub const UPLOAD_CHUNK_SIZE: usize = 64 * 1024;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Frame was empty — no verb byte.
    Empty,
    /// Verb byte is not one this build knows.
    UnknownVerb(u8),
    /// Ran off the end of the buffer while reading a field.
    Truncated { verb: u8, need: usize, have: usize },
    /// A declared length exceeds [`MAX_FRAME_BODY`].
    TooLarge { verb: u8, len: usize },
    /// A string field was not valid UTF-8.
    BadUtf8 { verb: u8 },
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty frame (no verb byte)"),
            Self::UnknownVerb(v) => write!(f, "unknown verb 0x{v:02x}"),
            Self::Truncated { verb, need, have } => {
                write!(
                    f,
                    "truncated frame for verb 0x{verb:02x}: need {need} more bytes, have {have}"
                )
            }
            Self::TooLarge { verb, len } => {
                write!(
                    f,
                    "verb 0x{verb:02x} declares {len} bytes, over the {MAX_FRAME_BODY} cap"
                )
            }
            Self::BadUtf8 { verb } => write!(f, "verb 0x{verb:02x} carries non-UTF-8 text"),
        }
    }
}

impl std::error::Error for ProtoError {}

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// Client → server. Round-trip probe.
    Echo {
        seq: u64,
        client_send_ns: u64,
        payload: Vec<u8>,
    },
    /// Server → client. The echo, with the server's own stamps so a four-point
    /// NTP-style clock-offset estimate is possible from the same exchange.
    EchoReply {
        seq: u64,
        client_send_ns: u64,
        server_recv_ns: u64,
        server_send_ns: u64,
        payload: Vec<u8>,
    },
    /// Client → server. Upload frame; the server counts and does not reply.
    Sink { seq: u64, payload: Vec<u8> },
    /// Client → server. End of an upload burst; asks for the server's tally.
    SinkEnd { frames: u64, bytes: u64 },
    /// Server → client. What the server *actually* received and decrypted —
    /// the cross-check that turns a throughput number into an assertion.
    SinkReport {
        frames: u64,
        bytes: u64,
        first_recv_ns: u64,
        last_recv_ns: u64,
    },
    /// Client → server. Ask the server to stream `total_bytes` back.
    SourceReq {
        total_bytes: u64,
        frame_size: u32,
        pace_kbps: u32,
    },
    /// Server → client. One download frame.
    SourceData {
        seq: u64,
        server_send_ns: u64,
        payload: Vec<u8>,
    },
    /// Server → client. Download complete.
    SourceEnd { frames: u64, bytes: u64 },
    /// Client → server. Request the server-side metrics snapshot.
    StatsReq,
    /// Server → client. JSON-encoded [`crate::report::ServerStats`].
    Stats { json: Vec<u8> },
    /// Either direction. Graceful end of the test conversation.
    Bye,
    /// Client → server. Begin a result-bundle file upload.
    UploadBegin { name: String, total_len: u64 },
    /// Client → server. One chunk of the file in flight.
    UploadChunk { data: Vec<u8> },
    /// Client → server. End of file; carries a checksum over the whole file.
    UploadEnd { checksum: u64 },
    /// Client → server. Timestamped marker in the server journal.
    ///
    /// Load-bearing for analysis: this is what lets a server-side periodic
    /// snapshot be attributed to the client scenario running at that instant.
    Mark { label: String },
}

impl Msg {
    /// The verb byte this message encodes to. Useful for logging a frame
    /// without cloning its payload.
    pub fn verb(&self) -> u8 {
        match self {
            Self::Echo { .. } => VERB_ECHO,
            Self::EchoReply { .. } => VERB_ECHO_REPLY,
            Self::Sink { .. } => VERB_SINK,
            Self::SinkEnd { .. } => VERB_SINK_END,
            Self::SinkReport { .. } => VERB_SINK_REPORT,
            Self::SourceReq { .. } => VERB_SOURCE_REQ,
            Self::SourceData { .. } => VERB_SOURCE_DATA,
            Self::SourceEnd { .. } => VERB_SOURCE_END,
            Self::StatsReq => VERB_STATS_REQ,
            Self::Stats { .. } => VERB_STATS,
            Self::Bye => VERB_BYE,
            Self::UploadBegin { .. } => VERB_UPLOAD_BEGIN,
            Self::UploadChunk { .. } => VERB_UPLOAD_CHUNK,
            Self::UploadEnd { .. } => VERB_UPLOAD_END,
            Self::Mark { .. } => VERB_MARK,
        }
    }

    /// A short, allocation-free name for logs.
    pub fn verb_name(&self) -> &'static str {
        verb_name(self.verb())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len_hint());
        out.push(self.verb());
        match self {
            Self::Echo {
                seq,
                client_send_ns,
                payload,
            } => {
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(&client_send_ns.to_be_bytes());
                out.extend_from_slice(payload);
            }
            Self::EchoReply {
                seq,
                client_send_ns,
                server_recv_ns,
                server_send_ns,
                payload,
            } => {
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(&client_send_ns.to_be_bytes());
                out.extend_from_slice(&server_recv_ns.to_be_bytes());
                out.extend_from_slice(&server_send_ns.to_be_bytes());
                out.extend_from_slice(payload);
            }
            Self::Sink { seq, payload } => {
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(payload);
            }
            Self::SinkEnd { frames, bytes } => {
                out.extend_from_slice(&frames.to_be_bytes());
                out.extend_from_slice(&bytes.to_be_bytes());
            }
            Self::SinkReport {
                frames,
                bytes,
                first_recv_ns,
                last_recv_ns,
            } => {
                out.extend_from_slice(&frames.to_be_bytes());
                out.extend_from_slice(&bytes.to_be_bytes());
                out.extend_from_slice(&first_recv_ns.to_be_bytes());
                out.extend_from_slice(&last_recv_ns.to_be_bytes());
            }
            Self::SourceReq {
                total_bytes,
                frame_size,
                pace_kbps,
            } => {
                out.extend_from_slice(&total_bytes.to_be_bytes());
                out.extend_from_slice(&frame_size.to_be_bytes());
                out.extend_from_slice(&pace_kbps.to_be_bytes());
            }
            Self::SourceData {
                seq,
                server_send_ns,
                payload,
            } => {
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(&server_send_ns.to_be_bytes());
                out.extend_from_slice(payload);
            }
            Self::SourceEnd { frames, bytes } => {
                out.extend_from_slice(&frames.to_be_bytes());
                out.extend_from_slice(&bytes.to_be_bytes());
            }
            Self::StatsReq | Self::Bye => {}
            Self::Stats { json } => out.extend_from_slice(json),
            Self::UploadBegin { name, total_len } => {
                let nb = name.as_bytes();
                out.extend_from_slice(&(nb.len() as u32).to_be_bytes());
                out.extend_from_slice(nb);
                out.extend_from_slice(&total_len.to_be_bytes());
            }
            Self::UploadChunk { data } => out.extend_from_slice(data),
            Self::UploadEnd { checksum } => out.extend_from_slice(&checksum.to_be_bytes()),
            Self::Mark { label } => out.extend_from_slice(label.as_bytes()),
        }
        out
    }

    fn encoded_len_hint(&self) -> usize {
        1 + match self {
            Self::Echo { payload, .. } => 16 + payload.len(),
            Self::EchoReply { payload, .. } => 32 + payload.len(),
            Self::Sink { payload, .. } => 8 + payload.len(),
            Self::SinkEnd { .. } | Self::SourceEnd { .. } => 16,
            Self::SinkReport { .. } => 32,
            Self::SourceReq { .. } => 16,
            Self::SourceData { payload, .. } => 16 + payload.len(),
            Self::StatsReq | Self::Bye => 0,
            Self::Stats { json } => json.len(),
            Self::UploadBegin { name, .. } => 12 + name.len(),
            Self::UploadChunk { data } => data.len(),
            Self::UploadEnd { .. } => 8,
            Self::Mark { label } => label.len(),
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let (&verb, rest) = buf.split_first().ok_or(ProtoError::Empty)?;
        if rest.len() > MAX_FRAME_BODY {
            return Err(ProtoError::TooLarge {
                verb,
                len: rest.len(),
            });
        }
        let mut c = Cursor::new(verb, rest);
        let msg = match verb {
            VERB_ECHO => Self::Echo {
                seq: c.u64()?,
                client_send_ns: c.u64()?,
                payload: c.rest(),
            },
            VERB_ECHO_REPLY => Self::EchoReply {
                seq: c.u64()?,
                client_send_ns: c.u64()?,
                server_recv_ns: c.u64()?,
                server_send_ns: c.u64()?,
                payload: c.rest(),
            },
            VERB_SINK => Self::Sink {
                seq: c.u64()?,
                payload: c.rest(),
            },
            VERB_SINK_END => Self::SinkEnd {
                frames: c.u64()?,
                bytes: c.u64()?,
            },
            VERB_SINK_REPORT => Self::SinkReport {
                frames: c.u64()?,
                bytes: c.u64()?,
                first_recv_ns: c.u64()?,
                last_recv_ns: c.u64()?,
            },
            VERB_SOURCE_REQ => Self::SourceReq {
                total_bytes: c.u64()?,
                frame_size: c.u32()?,
                pace_kbps: c.u32()?,
            },
            VERB_SOURCE_DATA => Self::SourceData {
                seq: c.u64()?,
                server_send_ns: c.u64()?,
                payload: c.rest(),
            },
            VERB_SOURCE_END => Self::SourceEnd {
                frames: c.u64()?,
                bytes: c.u64()?,
            },
            VERB_STATS_REQ => Self::StatsReq,
            VERB_STATS => Self::Stats { json: c.rest() },
            VERB_BYE => Self::Bye,
            VERB_UPLOAD_BEGIN => {
                let name_len = c.u32()? as usize;
                let name = c.utf8(name_len)?;
                Self::UploadBegin {
                    name,
                    total_len: c.u64()?,
                }
            }
            VERB_UPLOAD_CHUNK => Self::UploadChunk { data: c.rest() },
            VERB_UPLOAD_END => Self::UploadEnd { checksum: c.u64()? },
            VERB_MARK => {
                let n = c.remaining();
                Self::Mark { label: c.utf8(n)? }
            }
            other => return Err(ProtoError::UnknownVerb(other)),
        };
        Ok(msg)
    }
}

pub fn verb_name(v: u8) -> &'static str {
    match v {
        VERB_ECHO => "ECHO",
        VERB_ECHO_REPLY => "ECHO_REPLY",
        VERB_SINK => "SINK",
        VERB_SINK_END => "SINK_END",
        VERB_SINK_REPORT => "SINK_REPORT",
        VERB_SOURCE_REQ => "SOURCE_REQ",
        VERB_SOURCE_DATA => "SOURCE_DATA",
        VERB_SOURCE_END => "SOURCE_END",
        VERB_STATS_REQ => "STATS_REQ",
        VERB_STATS => "STATS",
        VERB_BYE => "BYE",
        VERB_UPLOAD_BEGIN => "UPLOAD_BEGIN",
        VERB_UPLOAD_CHUNK => "UPLOAD_CHUNK",
        VERB_UPLOAD_END => "UPLOAD_END",
        VERB_MARK => "MARK",
        _ => "UNKNOWN",
    }
}

// ── Bounded cursor ──────────────────────────────────────────────────────────

struct Cursor<'a> {
    verb: u8,
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(verb: u8, buf: &'a [u8]) -> Self {
        Self { verb, buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.remaining() < n {
            return Err(ProtoError::Truncated {
                verb: self.verb,
                need: n,
                have: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, ProtoError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64(&mut self) -> Result<u64, ProtoError> {
        let s = self.take(8)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn utf8(&mut self, n: usize) -> Result<String, ProtoError> {
        if n > MAX_FRAME_BODY {
            return Err(ProtoError::TooLarge {
                verb: self.verb,
                len: n,
            });
        }
        let s = self.take(n)?;
        String::from_utf8(s.to_vec()).map_err(|_| ProtoError::BadUtf8 { verb: self.verb })
    }

    fn rest(&mut self) -> Vec<u8> {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s.to_vec()
    }
}

// ── Checksum ────────────────────────────────────────────────────────────────

/// FNV-1a over the whole file, used to verify an uploaded result bundle.
///
/// Not a security primitive and not claimed to be one — the bundle already
/// travelled inside the session's AEAD. This exists to catch a truncated or
/// mis-reassembled upload, which is an integrity question, not an adversarial
/// one.
pub fn checksum(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ── Payload generation ──────────────────────────────────────────────────────

/// Deterministic, seedable payload filler (SplitMix64).
///
/// Deterministic so a run is reproducible; pseudo-random rather than a constant
/// pattern so nothing downstream can accidentally benefit from compressibility.
/// (Nothing on the Phantom data path compresses today — `PacketFlags::COMPRESSED`
/// is never set — but a constant payload would silently stop being a valid test
/// the day that changes.)
pub struct PayloadGen {
    state: u64,
}

impl PayloadGen {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn fill(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next_u64().to_be_bytes());
        }
        v.truncate(len);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(m: Msg) {
        let enc = m.encode();
        let dec = Msg::decode(&enc).expect("decode should accept our own encoding");
        assert_eq!(m, dec, "round-trip must be lossless for {}", m.verb_name());
    }

    #[test]
    fn every_message_round_trips() {
        round_trip(Msg::Echo {
            seq: 42,
            client_send_ns: 1_700_000_000_000_000_000,
            payload: vec![1, 2, 3, 4],
        });
        round_trip(Msg::EchoReply {
            seq: u64::MAX,
            client_send_ns: 1,
            server_recv_ns: 2,
            server_send_ns: 3,
            payload: vec![],
        });
        round_trip(Msg::Sink {
            seq: 7,
            payload: vec![0xAA; 1500],
        });
        round_trip(Msg::SinkEnd {
            frames: 10,
            bytes: 20,
        });
        round_trip(Msg::SinkReport {
            frames: 10,
            bytes: 20,
            first_recv_ns: 30,
            last_recv_ns: 40,
        });
        round_trip(Msg::SourceReq {
            total_bytes: 1 << 20,
            frame_size: 1024,
            pace_kbps: 0,
        });
        round_trip(Msg::SourceData {
            seq: 5,
            server_send_ns: 6,
            payload: vec![9; 100],
        });
        round_trip(Msg::SourceEnd {
            frames: 1,
            bytes: 2,
        });
        round_trip(Msg::StatsReq);
        round_trip(Msg::Stats {
            json: b"{\"a\":1}".to_vec(),
        });
        round_trip(Msg::Bye);
        round_trip(Msg::UploadBegin {
            name: "samples/udp/rtt_sweep.jsonl".to_string(),
            total_len: 123456,
        });
        round_trip(Msg::UploadChunk {
            data: vec![3; 4096],
        });
        round_trip(Msg::UploadEnd { checksum: 0xDEAD });
        round_trip(Msg::Mark {
            label: "scenario:rtt_sweep:begin".to_string(),
        });
    }

    #[test]
    fn empty_frame_is_typed_not_panic() {
        assert_eq!(Msg::decode(&[]), Err(ProtoError::Empty));
    }

    #[test]
    fn unknown_verb_is_typed() {
        assert_eq!(Msg::decode(&[0xFE]), Err(ProtoError::UnknownVerb(0xFE)));
    }

    /// Every verb that reads fixed-width fields must reject a body one byte
    /// short rather than panic. This is the property that keeps a garbled frame
    /// on a lossy WAN from taking the daemon down.
    #[test]
    fn truncated_bodies_are_rejected_for_every_fixed_width_verb() {
        for verb in [
            VERB_ECHO,
            VERB_ECHO_REPLY,
            VERB_SINK,
            VERB_SINK_END,
            VERB_SINK_REPORT,
            VERB_SOURCE_REQ,
            VERB_SOURCE_DATA,
            VERB_SOURCE_END,
            VERB_UPLOAD_BEGIN,
            VERB_UPLOAD_END,
        ] {
            for body_len in 0..8usize {
                let mut frame = vec![verb];
                frame.extend(std::iter::repeat_n(0u8, body_len));
                let got = Msg::decode(&frame);
                assert!(
                    matches!(
                        got,
                        Err(ProtoError::Truncated { .. }) | Err(ProtoError::TooLarge { .. })
                    ),
                    "verb {} with a {body_len}-byte body must be rejected, got {got:?}",
                    verb_name(verb)
                );
            }
        }
    }

    /// A hostile `UPLOAD_BEGIN` claiming a 4 GiB filename must not allocate it.
    #[test]
    fn oversized_declared_length_is_rejected_without_allocating() {
        let mut frame = vec![VERB_UPLOAD_BEGIN];
        frame.extend_from_slice(&u32::MAX.to_be_bytes());
        frame.extend_from_slice(&0u64.to_be_bytes());
        assert!(matches!(
            Msg::decode(&frame),
            Err(ProtoError::TooLarge { .. }) | Err(ProtoError::Truncated { .. })
        ));
    }

    #[test]
    fn non_utf8_mark_is_typed() {
        let frame = vec![VERB_MARK, 0xFF, 0xFE];
        assert_eq!(
            Msg::decode(&frame),
            Err(ProtoError::BadUtf8 { verb: VERB_MARK })
        );
    }

    #[test]
    fn body_over_the_cap_is_rejected() {
        let mut frame = vec![VERB_UPLOAD_CHUNK];
        frame.resize(MAX_FRAME_BODY + 2, 0);
        assert!(matches!(
            Msg::decode(&frame),
            Err(ProtoError::TooLarge { .. })
        ));
    }

    #[test]
    fn payload_gen_is_deterministic_and_exact_length() {
        let a = PayloadGen::new(7).fill(1000);
        let b = PayloadGen::new(7).fill(1000);
        let c = PayloadGen::new(8).fill(1000);
        assert_eq!(a, b, "same seed must produce the same payload");
        assert_ne!(a, c, "different seeds must differ");
        assert_eq!(a.len(), 1000);
        assert_eq!(PayloadGen::new(1).fill(0).len(), 0);
        assert_eq!(PayloadGen::new(1).fill(3).len(), 3);
    }

    #[test]
    fn checksum_detects_single_bit_flips() {
        let data = PayloadGen::new(1).fill(4096);
        let base = checksum(&data);
        for bit in [0usize, 1, 17, 4095 * 8 + 7] {
            let mut m = data.clone();
            m[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(
                checksum(&m),
                base,
                "bit {bit} flip must change the checksum"
            );
        }
        assert_ne!(checksum(&data[..4095]), base, "truncation must be caught");
    }
}
