//! Writes that give up on a peer which has stopped taking bytes.
//!
//! A stream socket's write waits for room in the kernel's send buffer, and that
//! room appears only as the peer reads. A peer that stops reading — a frozen
//! process, or a client that has decided to keep a server's session open — fills
//! the buffer and then holds every later write for as long as it likes. Inside a
//! session that write is the data pump's, so the peer would be holding the pump,
//! and with it the local close: nothing else in the pump's loop gets a turn until
//! the write returns.
//!
//! [`write_all_making_progress`] bounds the one quantity the peer controls, the
//! gap between two moments of progress. Any byte the socket accepts starts the
//! deadline again, so a link is never cut off for being slow; only a write that
//! has waited the whole deadline without the socket taking a single byte fails.
//! Bounding the total time instead would be a policy about how fast a peer has to
//! be, and that is the application's decision rather than the transport's.
//!
//! Used by `TcpSessionTransport`.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long a write may go without the socket accepting a byte before a stream
/// transport gives up on its peer.
///
/// Thirty seconds, which is the default `LivenessConfig::idle_timeout` — the
/// horizon over which a session gives up on a peer that has stopped answering,
/// and the one the reference server runs with. A peer that stops *reading* is
/// given the same.
///
/// It is deliberately not the session's configured `session_timeout`. The presets
/// set that to an hour or two, because it is how long a session waits for a
/// mobile peer that went quiet to migrate back — and a stream connection cannot
/// migrate, while a stalled write holds more than the session's slot: it holds
/// the pump itself, so for as long as it waits no liveness sweep and no local
/// close can run.
///
/// What counts as progress is what the socket reports, and the kernel wakes a
/// writer only once a sizeable share of a full send buffer has drained — about a
/// third of it on Linux. On a path whose rate has collapsed behind a buffer that
/// grew while it was fast, the gaps between wake-ups are longer than the byte
/// rate alone suggests. A deployment that expects such paths raises the deadline
/// on its transport.
pub(crate) const DEFAULT_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Why [`write_all_making_progress`] did not finish.
#[derive(Debug)]
pub(crate) enum WriteFailure {
    /// The socket accepted nothing for the whole deadline.
    Stalled,
    /// The socket reported an error.
    Io(io::Error),
}

/// Write every byte of `parts`, in order, then flush — failing with
/// [`WriteFailure::Stalled`] as soon as one step has waited `stall` without the
/// socket accepting anything.
///
/// Each part gets its own `write` calls, exactly as a `write_all` per part would
/// issue them, so the segments a caller puts on the wire do not change.
///
/// Cancelling a single `write` is safe — tokio guarantees nothing from a
/// cancelled call was written — but the bytes of earlier calls were. So a stall
/// can leave a message cut part-way through on the wire, and a caller whose
/// framing that breaks must not write on the connection again.
pub(crate) async fn write_all_making_progress<W>(
    writer: &mut W,
    parts: &[&[u8]],
    stall: Duration,
) -> Result<(), WriteFailure>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    for part in parts {
        let mut rest: &[u8] = part;
        while !rest.is_empty() {
            match tokio::time::timeout(stall, writer.write(rest)).await {
                Err(_) => return Err(WriteFailure::Stalled),
                Ok(Ok(0)) => return Err(WriteFailure::Io(io::ErrorKind::WriteZero.into())),
                // A writer that claims more than it was given has broken the
                // `AsyncWrite` contract; treating the claim as "all of it" ends the
                // loop rather than indexing past the slice.
                Ok(Ok(n)) => rest = rest.get(n..).unwrap_or(&[]),
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(e)) => return Err(WriteFailure::Io(e)),
            }
        }
    }
    match tokio::time::timeout(stall, writer.flush()).await {
        Err(_) => Err(WriteFailure::Stalled),
        Ok(flushed) => flushed.map_err(WriteFailure::Io),
    }
}

/// Make the connection end with a reset instead of an orderly close.
///
/// Called once a write has stalled out. What is still in the send buffer is
/// bytes the peer declined to take, and an orderly close would keep them — and
/// the connection's kernel state — while the kernel goes on offering them to a
/// peer with a closed window. A zero linger makes dropping the socket discard them
/// and send a reset, which releases everything at once and tells the peer plainly
/// that the connection was abandoned rather than finished. Only the zero case is
/// used: it is the one linger setting that never blocks the thread on close.
///
/// Best-effort: if the option cannot be set, the connection still ends — with the
/// orderly close it would have had anyway.
pub(crate) fn reset_on_close(stream: &TcpStream) {
    if let Err(e) = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO)) {
        log::debug!("could not arrange a reset for a stalled connection: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::liveness::LivenessConfig;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// The deadline's documentation rests on it being the session's default give-up
    /// horizon; if either moves, the reason written beside this one stops being true.
    #[test]
    fn the_default_write_stall_deadline_is_the_default_liveness_idle_timeout() {
        assert_eq!(
            DEFAULT_WRITE_STALL_TIMEOUT,
            LivenessConfig::default().idle_timeout
        );
    }

    /// A writer that accepts at most `per_call` bytes per call, and none at all
    /// once `budget` is spent — a socket whose peer reads a little and then stops.
    struct Trickle {
        per_call: usize,
        budget: usize,
        taken: Vec<u8>,
    }

    impl AsyncWrite for Trickle {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = buf.len().min(self.per_call).min(self.budget);
            if n == 0 {
                // Never woken again: the peer has stopped reading.
                return Poll::Pending;
            }
            self.budget -= n;
            self.taken.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Every byte of every part goes out, in order, however small the pieces the
    /// writer takes them in.
    #[tokio::test]
    async fn every_part_is_written_in_order_through_short_writes() {
        let mut w = Trickle {
            per_call: 3,
            budget: usize::MAX,
            taken: Vec::new(),
        };
        let outcome =
            write_all_making_progress(&mut w, &[b"head", b"", b"payload"], Duration::from_secs(5))
                .await;
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(w.taken, b"headpayload");
    }

    /// A writer that stops accepting part-way through fails the call as a stall,
    /// having taken exactly what it accepted before it stopped — the cut-off frame a
    /// caller must not write after.
    #[tokio::test]
    async fn a_writer_that_stops_accepting_is_reported_as_a_stall() {
        let mut w = Trickle {
            per_call: 4,
            budget: 6,
            taken: Vec::new(),
        };
        let outcome =
            write_all_making_progress(&mut w, &[b"0123456789"], Duration::from_millis(50)).await;
        assert!(matches!(outcome, Err(WriteFailure::Stalled)), "{outcome:?}");
        assert_eq!(w.taken, b"012345");
    }
}
