//! A local UDP relay that loses one datagram flight on purpose.
//!
//! Everything else in this harness measures what the path does. This measures what happens
//! when the path does something it will not do on demand.
//!
//! PhantomUDP's `ServerHello` is six datagrams of a thirteen-datagram handshake, and until
//! recently it was the only flight with no retransmission of its own: one datagram of it lost
//! on the way down cost the whole connect. The listener now retains the flight it sent and
//! repeats it, byte for byte, when the same question arrives again. Four measurement runs
//! across two days produced 76 consecutive successful UDP handshakes and no repeated flight at
//! all, because the path did not happen to lose a handshake datagram — so the repair has never
//! been observed working on a real path, and waiting for a lossy day is not a test strategy.
//!
//! The loss is therefore manufactured on the client side of a real connection. Every datagram
//! still crosses the WAN to the daemon and back; the relay decides only which of them reaches
//! the client's socket. What that buys is a real handshake against the real daemon, over the
//! real path, with one real flight deliberately missing.
//!
//! The decision lives in [`FlightSwallow`], apart from the sockets, so the rule that separates
//! "the loss happened" from "the path was clean" can be checked without a network.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use phantom_protocol::transport::phantom_udp::envelope::{
    decode_header, PacketType, FRAG_SUBHDR_LEN, PATH_MTU,
};
use tokio::net::UdpSocket;

/// Receive buffer for one datagram, with room to spare.
///
/// A datagram larger than the buffer is truncated by the kernel, and a truncated datagram
/// forwarded onwards is a corruption the peer reports as a protocol error — a different fault
/// wearing the costume of the one this relay exists to create.
const RELAY_BUF: usize = PATH_MTU + 64;

/// What one relay saw and what it did.
///
/// Shared with the task rather than returned by it, because the interesting figures have to be
/// readable while the connect they describe is still running, and afterwards without joining a
/// task that has no reason to have finished.
#[derive(Debug, Default)]
pub struct RelayStats {
    swallowed: AtomicUsize,
    flight_chunks: AtomicUsize,
    down_forwarded: AtomicUsize,
    up_forwarded: AtomicUsize,
}

impl RelayStats {
    /// Datagrams the relay refused to hand to the client.
    ///
    /// Zero after an armed run means the path carried no fragmented reply flight past this
    /// relay at all, and a connect that completed over it proves nothing about the repair.
    pub fn swallowed(&self) -> usize {
        self.swallowed.load(Ordering::Relaxed)
    }

    /// How many datagrams the doomed flight declared itself to be, from its own
    /// `total_chunks`. `None` until such a flight is seen.
    ///
    /// Read beside [`Self::swallowed`]: the two differ when the WAN lost part of the flight
    /// before the relay saw it, which leaves swallow budget to spend on the repeat that
    /// follows. That costs the connect an extra retransmit rather than the result.
    pub fn flight_chunks(&self) -> Option<u16> {
        u16::try_from(self.flight_chunks.load(Ordering::Relaxed))
            .ok()
            .filter(|n| *n > 0)
    }

    /// Datagrams delivered to the client, and to the server, respectively.
    ///
    /// The relay's own positive control: a run where nothing crossed in either direction is a
    /// relay that never worked, which is a different thing from a path that never lost
    /// anything, and the counters are what tell them apart.
    pub fn down_forwarded(&self) -> usize {
        self.down_forwarded.load(Ordering::Relaxed)
    }

    pub fn up_forwarded(&self) -> usize {
        self.up_forwarded.load(Ordering::Relaxed)
    }
}

/// Decides which server → client datagrams never reach the client.
///
/// The rule is fragment identity, not a clock and not a coin: the first fragmented handshake
/// datagram coming down names the size of its own flight in `total_chunks`, and that many
/// datagrams are swallowed. Exactly one flight goes missing however many datagrams it is made
/// of, and every later flight — including the listener's repeat — arrives.
///
/// Only one message in a PhantomUDP handshake fragments. `HelloRetryRequest` is tens of bytes
/// and `ServerReject` is smaller still, while `ServerHello` carries a hybrid KEM ciphertext and
/// a ~4 KB hybrid signature and spends six datagrams on it. So "the first fragmented downstream
/// handshake flight" names the reply the connect turns on, without this relay parsing a
/// handshake message or holding a key.
///
/// It deliberately does **not** key on the fragment's `packet_id`, which would be the obvious
/// way to name a flight. The listener's repeat is the retained flight byte for byte, so it
/// carries the same `packet_id` as the flight that was lost, and a rule keyed on that would
/// swallow the repair along with the thing it repairs — a scenario that could never pass.
pub struct FlightSwallow {
    armed: bool,
    /// Datagrams of the doomed flight still to be swallowed. `None` until a fragmented
    /// downstream handshake datagram names the size of its own flight.
    owed: Option<usize>,
    stats: Arc<RelayStats>,
}

impl FlightSwallow {
    pub fn new(armed: bool, stats: Arc<RelayStats>) -> Self {
        Self {
            armed,
            owed: None,
            stats,
        }
    }

    /// `true` when this datagram must not be delivered.
    ///
    /// A datagram whose envelope will not decode is forwarded untouched. Refusing to parse is
    /// not licence to drop: this relay's whole claim is that it removes one identified flight
    /// and nothing else, and a parse failure is the relay's problem rather than the datagram's.
    pub fn judge(&mut self, datagram: &[u8]) -> bool {
        if !self.armed {
            return false;
        }
        let Ok((hdr, rest)) = decode_header(datagram) else {
            return false;
        };
        // Handshake-typed and fragmented, together: an established session's fragmented
        // application data is not a reply flight, and swallowing it would be measuring
        // something else entirely.
        if hdr.ty != PacketType::Initial || !hdr.fragmented || rest.len() < FRAG_SUBHDR_LEN {
            return false;
        }
        if self.owed.is_none() {
            let total = u16::from_be_bytes([rest[6], rest[7]]);
            self.owed = Some(total as usize);
            self.stats
                .flight_chunks
                .store(total as usize, Ordering::Relaxed);
        }
        let remaining = self.owed.unwrap_or(0);
        if remaining == 0 {
            return false;
        }
        self.owed = Some(remaining - 1);
        self.stats.swallowed.fetch_add(1, Ordering::Relaxed);
        true
    }
}

/// A running relay between a local client socket and a remote daemon.
///
/// Aborted on drop, so a scenario that spawns one per attempt cannot leave a fleet of them
/// forwarding into a daemon it has finished measuring.
pub struct Relay {
    addr: SocketAddr,
    stats: Arc<RelayStats>,
    task: tokio::task::JoinHandle<()>,
}

impl Relay {
    /// Stand a relay in front of `server`, arming the swallow or not.
    ///
    /// The disarmed form is not a convenience — it is the denominator. A connect through it
    /// pays the same loopback hop and the same WAN path as the armed one, so the difference
    /// between the two elapsed times is the loss and nothing else. Without it the armed
    /// figure would have to be compared against a connect that never went through a relay,
    /// and the comparison would carry the relay's own cost inside it.
    pub async fn spawn(server: SocketAddr, armed: bool) -> std::io::Result<Self> {
        // Bound to the loopback family the client will use to reach it, so the two ends of the
        // local hop cannot end up on different address families.
        let downstream = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = downstream.local_addr()?;
        let upstream = UdpSocket::bind(if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        upstream.connect(server).await?;

        let stats = Arc::new(RelayStats::default());
        let mut swallow = FlightSwallow::new(armed, stats.clone());
        let task_stats = stats.clone();
        let task = tokio::spawn(async move {
            let mut up_buf = vec![0u8; RELAY_BUF];
            let mut down_buf = vec![0u8; RELAY_BUF];
            let mut client: Option<SocketAddr> = None;
            loop {
                tokio::select! {
                    r = downstream.recv_from(&mut up_buf) => {
                        let Ok((n, from)) = r else { continue };
                        client = Some(from);
                        if upstream.send(&up_buf[..n]).await.is_ok() {
                            task_stats.up_forwarded.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    r = upstream.recv(&mut down_buf) => {
                        let Ok(n) = r else { continue };
                        let datagram = &down_buf[..n];
                        if swallow.judge(datagram) {
                            continue;
                        }
                        if let Some(c) = client {
                            if downstream.send_to(datagram, c).await.is_ok() {
                                task_stats.down_forwarded.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        });

        Ok(Self { addr, stats, task })
    }

    /// Where a client should point itself.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn stats(&self) -> &Arc<RelayStats> {
        &self.stats
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_protocol::transport::phantom_udp::datagram::encode_datagrams;
    use phantom_protocol::transport::phantom_udp::envelope::{encode_header, MAX_INNER_FRAG_CHUNK};

    fn stats() -> Arc<RelayStats> {
        Arc::new(RelayStats::default())
    }

    /// A fragmented flight of exactly `chunks` datagrams, as the encoder would produce it.
    ///
    /// The body is sized off `MAX_INNER_FRAG_CHUNK` rather than a round number, because the
    /// encoder chunks by that constant: any other size fragments into a count the test would
    /// then be asserting against by luck.
    fn flight_of(ty: PacketType, cid: u8, packet_id: u32, chunks: usize) -> Vec<Vec<u8>> {
        let body = vec![cid; MAX_INNER_FRAG_CHUNK * chunks];
        encode_datagrams(ty, &[cid; 8], packet_id, &body).expect("encodes")
    }

    fn flight(cid: u8, packet_id: u32, chunks: usize) -> Vec<Vec<u8>> {
        flight_of(PacketType::Initial, cid, packet_id, chunks)
    }

    fn single(ty: PacketType, cid: u8) -> Vec<u8> {
        let mut d = Vec::new();
        encode_header(&mut d, ty, false, &[cid; 8]);
        d.extend_from_slice(b"short");
        d
    }

    /// The whole of the first flight goes, and nothing of the second.
    ///
    /// This is the property the scenario rests on: the listener's repeat is a second flight,
    /// so a rule that took one datagram too many would swallow the repair and report the
    /// repaired protocol as broken.
    #[test]
    fn exactly_one_flight_is_swallowed_however_long_it_is() {
        for chunks in [2usize, 3, 6, 11] {
            let s = stats();
            let mut sw = FlightSwallow::new(true, s.clone());
            let first = flight(1, 7, chunks);
            assert_eq!(first.len(), chunks, "the fixture must fragment as expected");
            for d in &first {
                assert!(sw.judge(d), "every datagram of the first flight goes");
            }
            // Byte for byte the same flight — which is precisely what the listener repeats,
            // packet_id included. Keying on that id would swallow this too.
            for d in &first {
                assert!(!sw.judge(d), "the repeat must arrive");
            }
            assert_eq!(s.swallowed(), chunks);
            assert_eq!(s.flight_chunks(), Some(chunks as u16));
        }
    }

    /// Everything that is not a fragmented handshake flight passes untouched.
    #[test]
    fn only_a_fragmented_handshake_flight_is_eligible() {
        let s = stats();
        let mut sw = FlightSwallow::new(true, s.clone());

        // A HelloRetryRequest fits one datagram: it is downstream and handshake-typed, and
        // must still cross, or the client never gets as far as the reply this is about.
        assert!(!sw.judge(&single(PacketType::Initial, 2)));
        // Established-session traffic, fragmented or not, is not a reply flight.
        assert!(!sw.judge(&single(PacketType::OneRtt, 2)));
        for d in flight_of(PacketType::OneRtt, 9, 1, 3) {
            assert!(
                !sw.judge(&d),
                "application fragments are not a reply flight"
            );
        }
        // Nothing a parser can make sense of.
        assert!(!sw.judge(&[]));
        assert!(!sw.judge(&[0xff]));
        // A fragment header cut short of its own sub-header.
        let mut stub = Vec::new();
        encode_header(&mut stub, PacketType::Initial, true, &[3u8; 8]);
        stub.extend_from_slice(&[0u8; FRAG_SUBHDR_LEN - 1]);
        assert!(!sw.judge(&stub));

        assert_eq!(s.swallowed(), 0);
        assert_eq!(
            s.flight_chunks(),
            None,
            "no flight was identified, so none may be reported"
        );

        // And the eligible flight that follows all of that is still taken.
        for d in &flight(4, 12, 3) {
            assert!(sw.judge(d));
        }
        assert_eq!(s.swallowed(), 3);
    }

    /// Disarmed, it is a plain forwarder. The baseline connect the armed one is compared
    /// against depends on this being true, not nearly true.
    #[test]
    fn a_disarmed_swallow_takes_nothing() {
        let s = stats();
        let mut sw = FlightSwallow::new(false, s.clone());
        for d in &flight(5, 3, 6) {
            assert!(!sw.judge(d));
        }
        assert_eq!(s.swallowed(), 0);
        assert_eq!(s.flight_chunks(), None);
    }

    /// The relay carries datagrams both ways, and the armed one removes the flight it named.
    ///
    /// Driven against a plain echo socket rather than a daemon: what is under test here is the
    /// relay, and a real handshake would put the protocol's own behaviour between the assertion
    /// and the thing it asserts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_relay_forwards_both_ways_and_drops_the_flight_it_named() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("echo socket");
        let server_addr = server.local_addr().expect("echo addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; RELAY_BUF];
            while let Ok((n, from)) = server.recv_from(&mut buf).await {
                // Answer each datagram with a whole fragmented flight, the shape of a reply
                // the client has to reassemble.
                for d in flight(8, 1, 4) {
                    let _ = server.send_to(&d, from).await;
                }
                let _ = n;
            }
        });

        let relay = Relay::spawn(server_addr, true).await.expect("relay binds");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client socket");
        client.connect(relay.addr()).await.expect("client connect");

        // First question: its whole answer is swallowed, so nothing comes back.
        client.send(b"q1").await.expect("send");
        let mut buf = vec![0u8; RELAY_BUF];
        let heard =
            tokio::time::timeout(std::time::Duration::from_millis(500), client.recv(&mut buf))
                .await;
        assert!(
            heard.is_err(),
            "the first flight must not reach the client, got {heard:?}"
        );
        assert_eq!(relay.stats().swallowed(), 4);
        assert_eq!(relay.stats().flight_chunks(), Some(4));

        // Second question: the same answer, and this time all of it arrives.
        client.send(b"q2").await.expect("send");
        for _ in 0..4 {
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.recv(&mut buf))
                .await
                .expect("the repeat must cross")
                .expect("a datagram");
            assert!(n > 0);
        }
        assert_eq!(
            relay.stats().swallowed(),
            4,
            "only one flight may ever be taken"
        );
        assert!(relay.stats().up_forwarded() >= 2);
        assert!(relay.stats().down_forwarded() >= 4);
    }

    /// A disarmed relay delivers the same flight the armed one removed. Without this the
    /// scenario's baseline could be silently measuring a relay that drops everything.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_disarmed_relay_delivers_the_flight() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("echo socket");
        let server_addr = server.local_addr().expect("echo addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; RELAY_BUF];
            while let Ok((_, from)) = server.recv_from(&mut buf).await {
                for d in flight(8, 1, 4) {
                    let _ = server.send_to(&d, from).await;
                }
            }
        });

        let relay = Relay::spawn(server_addr, false).await.expect("relay binds");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client socket");
        client.connect(relay.addr()).await.expect("client connect");
        client.send(b"q").await.expect("send");

        let mut buf = vec![0u8; RELAY_BUF];
        for _ in 0..4 {
            tokio::time::timeout(std::time::Duration::from_secs(5), client.recv(&mut buf))
                .await
                .expect("every datagram must cross a disarmed relay")
                .expect("a datagram");
        }
        assert_eq!(relay.stats().swallowed(), 0);
    }
}
