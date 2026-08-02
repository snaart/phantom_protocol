//! Message framing over a Phantom session.
//!
//! ## Why this exists
//!
//! `PhantomSession::send()` is **not message-preserving**. The data pump splits
//! any payload larger than its internal `TRANSPORT_MTU` (1300 B) into
//! 1300-byte chunks and writes each as a separate reliable-stream write; the
//! peer's `recv()` then yields each chunk as its own result. A caller that
//! sends 8 KiB and expects one `recv()` of 8 KiB instead gets seven.
//!
//! That behaviour is undocumented on `send`/`recv`, and it is silent: the first
//! chunk of a structured message still parses as a valid — but truncated —
//! message, so a naive harness records a *successful* round trip while the
//! payload was quietly cut. This harness hit exactly that and briefly believed
//! large payloads were working.
//!
//! So every testbed message carries its own 4-byte big-endian length prefix and
//! is reassembled here. That makes the harness correct on every leg regardless
//! of chunking — and, because the reassembler counts the chunks each logical
//! message arrived in, it turns the underlying behaviour into a measurement
//! rather than a trap. See the `message_integrity` scenario.

use std::sync::Arc;

use phantom_protocol::api::session::PhantomSession;
use phantom_protocol::CoreError;
use tokio::sync::Mutex;

use crate::proto::{Msg, MAX_FRAME_BODY};

/// Length-prefix width. Matches `TcpSessionTransport`'s own framing choice.
const LEN_PREFIX: usize = 4;

/// Upper bound on a reassembled message, with room for the verb byte.
const MAX_MESSAGE: usize = MAX_FRAME_BODY + 1;

/// How a logical message arrived: how many transport reads it took, and how
/// large each was.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arrival {
    /// Number of `PhantomSession::recv()` results consumed for this message.
    ///
    /// `1` means the session preserved the message boundary. Anything greater
    /// means the payload was split in transit and only reassembly recovered it.
    pub chunks: usize,
    /// Sizes of those reads, in order.
    pub chunk_sizes: Vec<usize>,
    /// Length of the reassembled message.
    pub message_len: usize,
}

/// A Phantom session with message framing layered on top.
pub struct Framed {
    session: Arc<PhantomSession>,
    rx: Mutex<RxState>,
}

#[derive(Default)]
struct RxState {
    buf: Vec<u8>,
    /// Reads consumed since the last complete message was returned.
    pending_chunks: Vec<usize>,
}

impl Framed {
    pub fn new(session: Arc<PhantomSession>) -> Self {
        Self {
            session,
            rx: Mutex::new(RxState::default()),
        }
    }

    pub fn session(&self) -> &Arc<PhantomSession> {
        &self.session
    }

    /// Frame and send one message.
    pub async fn send(&self, msg: &Msg) -> Result<(), CoreError> {
        self.session.send(encode_framed(msg)).await
    }

    /// Send bytes already produced by [`encode_framed`].
    ///
    /// Lets a saturating send loop encode once and reuse both the buffer and
    /// its length, instead of encoding a second time just to learn how many
    /// bytes it offered.
    pub async fn send_encoded(&self, framed: Vec<u8>) -> Result<(), CoreError> {
        self.session.send(framed).await
    }

    /// Receive one complete message, reassembling across transport reads.
    ///
    /// Also returns how the message arrived, so a caller can observe splitting
    /// instead of merely surviving it.
    pub async fn recv(&self) -> Result<(Msg, Arrival), CoreError> {
        let mut st = self.rx.lock().await;
        loop {
            if let Some((msg, arrival)) = take_message(&mut st)? {
                return Ok((msg, arrival));
            }
            let chunk = self.session.recv().await?;
            st.pending_chunks.push(chunk.len());
            st.buf.extend_from_slice(&chunk);
        }
    }
}

/// Encode a message with its length prefix.
pub fn encode_framed(msg: &Msg) -> Vec<u8> {
    let body = msg.encode();
    let mut out = Vec::with_capacity(LEN_PREFIX + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Pull one complete message out of the accumulator, if there is one.
fn take_message(st: &mut RxState) -> Result<Option<(Msg, Arrival)>, CoreError> {
    if st.buf.len() < LEN_PREFIX {
        return Ok(None);
    }
    let len = u32::from_be_bytes([st.buf[0], st.buf[1], st.buf[2], st.buf[3]]) as usize;
    if len > MAX_MESSAGE {
        // A length this large means the stream is desynchronised. Failing
        // loudly beats allocating on a corrupt header.
        return Err(CoreError::ProtocolRejected(format!(
            "framed length {len} exceeds the {MAX_MESSAGE} cap"
        )));
    }
    if st.buf.len() < LEN_PREFIX + len {
        return Ok(None);
    }

    let body = st.buf[LEN_PREFIX..LEN_PREFIX + len].to_vec();
    st.buf.drain(..LEN_PREFIX + len);

    let chunk_sizes = std::mem::take(&mut st.pending_chunks);
    let arrival = Arrival {
        chunks: chunk_sizes.len(),
        chunk_sizes,
        message_len: len,
    };

    let msg =
        Msg::decode(&body).map_err(|e| CoreError::ProtocolRejected(format!("framed body: {e}")))?;
    Ok(Some((msg, arrival)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::PayloadGen;

    /// Feed the reassembler a byte stream in arbitrary chunk sizes and collect
    /// the messages it yields, exactly as `Framed::recv` would.
    fn drain(chunks: &[Vec<u8>]) -> Vec<(Msg, Arrival)> {
        let mut st = RxState::default();
        let mut out = Vec::new();
        for c in chunks {
            st.pending_chunks.push(c.len());
            st.buf.extend_from_slice(c);
            while let Some(v) = take_message(&mut st).expect("no framing error") {
                out.push(v);
            }
        }
        out
    }

    #[test]
    fn a_message_delivered_whole_reports_one_chunk() {
        let msg = Msg::Echo {
            seq: 1,
            client_send_ns: 2,
            payload: vec![7; 100],
        };
        let got = drain(&[encode_framed(&msg)]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, msg);
        assert_eq!(got[0].1.chunks, 1, "an unsplit message must report 1 chunk");
    }

    /// The case this module exists for: an 8 KiB message split into 1300-byte
    /// transport reads must come back byte-identical, and must *report* that it
    /// was split.
    #[test]
    fn a_message_split_at_1300_bytes_is_reassembled_and_reported() {
        let payload = PayloadGen::new(5).fill(8192);
        let msg = Msg::Echo {
            seq: 42,
            client_send_ns: 99,
            payload: payload.clone(),
        };
        let wire = encode_framed(&msg);
        let chunks: Vec<Vec<u8>> = wire.chunks(1300).map(|c| c.to_vec()).collect();
        assert!(chunks.len() > 1, "the test must actually split something");

        let got = drain(&chunks);
        assert_eq!(got.len(), 1, "one logical message");
        assert_eq!(got[0].0, msg, "reassembly must be byte-exact");
        assert_eq!(got[0].1.chunks, chunks.len());
        assert_eq!(got[0].1.message_len, msg.encode().len());
        assert!(
            got[0]
                .1
                .chunk_sizes
                .iter()
                .take(chunks.len() - 1)
                .all(|&n| n == 1300),
            "chunk sizes are recorded verbatim: {:?}",
            got[0].1.chunk_sizes
        );
    }

    /// Several messages coalesced into one transport read must all come out.
    #[test]
    fn coalesced_messages_are_all_recovered() {
        let a = Msg::Mark { label: "a".into() };
        let b = Msg::Bye;
        let c = Msg::Sink {
            seq: 3,
            payload: vec![1, 2, 3],
        };
        let mut one = encode_framed(&a);
        one.extend_from_slice(&encode_framed(&b));
        one.extend_from_slice(&encode_framed(&c));

        let got = drain(&[one]);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, a);
        assert_eq!(got[1].0, b);
        assert_eq!(got[2].0, c);
    }

    /// Byte-at-a-time delivery is the pathological case for any reassembler.
    #[test]
    fn one_byte_at_a_time_still_reassembles() {
        let msg = Msg::Sink {
            seq: 9,
            payload: PayloadGen::new(1).fill(300),
        };
        let wire = encode_framed(&msg);
        let chunks: Vec<Vec<u8>> = wire.iter().map(|b| vec![*b]).collect();
        let got = drain(&chunks);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, msg);
        assert_eq!(got[0].1.chunks, wire.len());
    }

    #[test]
    fn a_partial_message_yields_nothing_rather_than_a_truncated_one() {
        let msg = Msg::Sink {
            seq: 1,
            payload: vec![4; 500],
        };
        let wire = encode_framed(&msg);
        let got = drain(&[wire[..wire.len() - 1].to_vec()]);
        assert!(
            got.is_empty(),
            "an incomplete message must not be delivered at all"
        );
    }

    #[test]
    fn an_absurd_declared_length_is_rejected_without_allocating() {
        let mut st = RxState::default();
        st.buf.extend_from_slice(&u32::MAX.to_be_bytes());
        st.buf.extend_from_slice(&[0u8; 16]);
        let r = take_message(&mut st);
        assert!(matches!(r, Err(CoreError::ProtocolRejected(_))), "{r:?}");
    }

    #[test]
    fn a_desynchronised_body_is_a_typed_error() {
        let mut st = RxState::default();
        // Declares 2 bytes, body is an unknown verb.
        st.buf.extend_from_slice(&2u32.to_be_bytes());
        st.buf.extend_from_slice(&[0xFE, 0x00]);
        let r = take_message(&mut st);
        assert!(matches!(r, Err(CoreError::ProtocolRejected(_))), "{r:?}");
    }

    #[test]
    fn arrival_chunk_accounting_resets_between_messages() {
        let a = Msg::Sink {
            seq: 1,
            payload: vec![0; 2000],
        };
        let b = Msg::Sink {
            seq: 2,
            payload: vec![0; 10],
        };
        let mut wire = encode_framed(&a);
        wire.extend_from_slice(&encode_framed(&b));
        let chunks: Vec<Vec<u8>> = wire.chunks(700).map(|c| c.to_vec()).collect();

        let got = drain(&chunks);
        assert_eq!(got.len(), 2);
        // The second message must not inherit the first message's chunk count.
        assert!(
            got[1].1.chunks <= got[0].1.chunks,
            "chunk counters leaked between messages: {:?} then {:?}",
            got[0].1,
            got[1].1
        );
        assert_eq!(got[0].1.message_len, a.encode().len());
        assert_eq!(got[1].1.message_len, b.encode().len());
    }
}
