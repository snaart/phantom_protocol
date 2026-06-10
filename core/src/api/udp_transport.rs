//! `SessionTransport` impls over raw UDP (PhantomUDP). `UdpClientTransport` is a connected-socket
//! client; a later task adds `UdpServerTransport` (a per-session shim fed by the listener demux). Both
//! add / strip the outer `[flags][cid]` envelope exactly as `TcpSessionTransport` adds / strips its
//! 4-byte length prefix, so `run_data_pump` / `run_client_handshake` / `drive_server_handshake` are reused.

use crate::api::session::{FramePhase, SessionTransport};
use crate::errors::CoreError;
use crate::transport::phantom_udp::datagram::{encode_datagrams, push_datagram, FragmentAssembler};
use crate::transport::phantom_udp::envelope::{ConnId, PacketType, PATH_MTU};
// `HDR_LEN` is referenced only by the test module (`super::HDR_LEN`); a plain top-level
// import trips clippy's `--lib` unused-import check, which excludes `#[cfg(test)]` code.
#[cfg(test)]
use crate::transport::phantom_udp::envelope::HDR_LEN;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

/// Retransmit timeout for the Handshake phase stop-and-wait shim.
const HANDSHAKE_RTO: Duration = Duration::from_millis(400);
/// Max Handshake-phase retransmits before giving up (the outer 10s connect deadline still applies).
const MAX_HANDSHAKE_RETX: u32 = 6;

const PHASE_HANDSHAKE: u8 = 0;
const PHASE_ESTABLISHED: u8 = 1;

pub struct UdpClientTransport {
    socket: Arc<UdpSocket>,
    cid: ConnId,
    phase: AtomicU8,
    next_packet_id: AtomicU32,
    /// Datagrams of the most recently sent frame, retransmitted on RTO during Handshake.
    last_sent: Mutex<Vec<Vec<u8>>>,
    reasm: Mutex<FragmentAssembler>,
}

impl UdpClientTransport {
    /// Connect a fresh UDP socket to `server`, choosing a random lifetime connection-ID.
    pub async fn connect(server: SocketAddr) -> Result<Self, CoreError> {
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp bind: {e}")))?;
        socket
            .connect(server)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp connect: {e}")))?;
        let mut cid = [0u8; 8];
        getrandom::getrandom(&mut cid).map_err(|e| CoreError::RngError(e.to_string()))?;
        Ok(Self {
            socket: Arc::new(socket),
            cid,
            phase: AtomicU8::new(PHASE_HANDSHAKE),
            next_packet_id: AtomicU32::new(0),
            last_sent: Mutex::new(Vec::new()),
            reasm: Mutex::new(FragmentAssembler::new()),
        })
    }

    /// The connection-ID this client stamps on every datagram (test/inspection helper).
    // Only called from the `#[cfg(test)]` module; `--lib` clippy excludes test code, so the
    // dead-code lint would fire without this allow.
    #[allow(dead_code)]
    pub(crate) fn cid(&self) -> ConnId {
        self.cid
    }

    fn pkt_id(&self) -> u32 {
        self.next_packet_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl SessionTransport for UdpClientTransport {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        // Handshake frames are Initial (long header); post-handshake frames are OneRtt (short header).
        let ty = if self.phase.load(Ordering::Relaxed) == PHASE_HANDSHAKE {
            PacketType::Initial
        } else {
            PacketType::OneRtt
        };
        let dgrams = encode_datagrams(ty, &self.cid, self.pkt_id(), data)
            .map_err(|e| CoreError::NetworkError(format!("frame too large to fragment: {e}")))?;
        for d in &dgrams {
            self.socket
                .send(d)
                .await
                .map_err(|e| CoreError::NetworkError(format!("udp send: {e}")))?;
        }
        // Remember for Handshake-phase retransmit (ignored once Established).
        *self.last_sent.lock().await = dgrams;
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        // Sized at PATH_MTU + slack. We only ever emit datagrams <= PATH_MTU, so a legitimate peer
        // never exceeds this; an oversized datagram is truncated by `recv` and then dropped by the
        // `decode_header`/reassembly failure path below — intentional.
        let mut buf = vec![0u8; PATH_MTU + 64];
        let mut retx = 0u32;
        loop {
            let in_handshake = self.phase.load(Ordering::Relaxed) == PHASE_HANDSHAKE;
            // Inline the recv future directly in `select!` (select! pins it internally). When the
            // recv arm wins, its future is dropped, releasing the `&mut buf` borrow before we slice
            // `&buf[..n]`. When the RTO arm wins, the recv future is dropped too, then we retransmit.
            let n = if in_handshake {
                tokio::select! {
                    r = self.socket.recv(&mut buf) =>
                        r.map_err(|e| CoreError::NetworkError(format!("udp recv: {e}")))?,
                    _ = tokio::time::sleep(HANDSHAKE_RTO) => {
                        retx += 1;
                        if retx > MAX_HANDSHAKE_RETX {
                            return Err(CoreError::Timeout);
                        }
                        for d in self.last_sent.lock().await.iter() {
                            let _ = self.socket.send(d).await;
                        }
                        continue;
                    }
                }
            } else {
                self.socket
                    .recv(&mut buf)
                    .await
                    .map_err(|e| CoreError::NetworkError(format!("udp recv: {e}")))?
            };
            retx = 0; // progress: reset the RTO budget
            let mut asm = self.reasm.lock().await;
            match push_datagram(&mut asm, &buf[..n]) {
                Ok((_hdr, Some(frame))) => return Ok(Bytes::from(frame)),
                Ok((_hdr, None)) => continue, // partial fragment; keep receiving
                Err(_) => continue,           // malformed datagram; drop and keep receiving
            }
        }
    }

    fn set_frame_phase(&self, phase: FramePhase) {
        let v = match phase {
            FramePhase::Handshake => PHASE_HANDSHAKE,
            FramePhase::Established => PHASE_ESTABLISHED,
        };
        self.phase.store(v, Ordering::Relaxed);
    }
}

/// Per-session server transport. The listener's demux task reassembles inbound datagrams and pushes
/// the inner frames to `rx`; outbound frames are enveloped and sent to the captured `peer`.
// `new` has no caller outside of tests yet — the listener task (a later task) will wire it up.
#[allow(dead_code)]
pub struct UdpServerTransport {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    cid: ConnId,
    phase: AtomicU8,
    next_packet_id: AtomicU32,
    rx: Mutex<mpsc::Receiver<Bytes>>,
}

impl UdpServerTransport {
    // No caller outside tests yet; the listener task will wire this up.
    #[allow(dead_code)]
    pub fn new(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        cid: ConnId,
        rx: mpsc::Receiver<Bytes>,
    ) -> Self {
        Self {
            socket,
            peer,
            cid,
            phase: AtomicU8::new(PHASE_HANDSHAKE),
            next_packet_id: AtomicU32::new(0),
            rx: Mutex::new(rx),
        }
    }
}

impl SessionTransport for UdpServerTransport {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        let ty = if self.phase.load(Ordering::Relaxed) == PHASE_HANDSHAKE {
            PacketType::Initial
        } else {
            PacketType::OneRtt
        };
        let pid = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let dgrams = encode_datagrams(ty, &self.cid, pid, data)
            .map_err(|e| CoreError::NetworkError(format!("frame too large to fragment: {e}")))?;
        for d in &dgrams {
            self.socket
                .send_to(d, self.peer)
                .await
                .map_err(|e| CoreError::NetworkError(format!("udp send_to: {e}")))?;
        }
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreError::ConnectionClosed)
    }

    fn set_frame_phase(&self, phase: FramePhase) {
        let v = match phase {
            FramePhase::Handshake => PHASE_HANDSHAKE,
            FramePhase::Established => PHASE_ESTABLISHED,
        };
        self.phase.store(v, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::phantom_udp::datagram::{push_datagram, FragmentAssembler};
    use crate::transport::phantom_udp::envelope::PacketType;
    use tokio::net::UdpSocket;

    /// A framed frame round-trips client -> raw peer -> client, including a >MTU
    /// (fragmented) reply that `recv_bytes` reassembles.
    #[tokio::test]
    async fn client_send_recv_with_fragmented_reply() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let client = UdpClientTransport::connect(peer_addr).await.unwrap();

        // Client sends a small frame.
        client.send_bytes(b"hello").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        let mut asm = FragmentAssembler::new();
        let (_h, got) = push_datagram(&mut asm, &buf[..n]).unwrap();
        assert_eq!(got.as_deref(), Some(&b"hello"[..]));

        // Peer replies with a >MTU frame (fragments); client reassembles via recv_bytes.
        let big: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        for d in encode_datagrams(PacketType::OneRtt, &client.cid(), 1, &big).expect("encode") {
            peer.send_to(&d, from).await.unwrap();
        }
        let recv = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_bytes())
            .await
            .expect("no timeout")
            .expect("recv");
        assert_eq!(&recv[..], &big[..]);
    }

    /// While in Handshake phase, a dropped first datagram is retransmitted on RTO.
    #[tokio::test]
    async fn client_retransmits_handshake_on_rto() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let client = UdpClientTransport::connect(peer_addr).await.unwrap();
        // default phase is Handshake.
        let send = async {
            client.send_bytes(b"flight1").await.unwrap();
        };
        let mut buf = vec![0u8; 2048];
        // Peer ignores the first datagram, reads the retransmit.
        let recv = async {
            let _ = peer.recv_from(&mut buf).await.unwrap(); // drop #1
            let (n, from) = peer.recv_from(&mut buf).await.unwrap(); // retransmit
                                                                     // Reply so client's recv_bytes completes.
            for d in
                encode_datagrams(PacketType::Initial, &client.cid(), 0, b"reply").expect("encode")
            {
                peer.send_to(&d, from).await.unwrap();
            }
            n
        };
        let recv_client = async {
            tokio::time::timeout(std::time::Duration::from_secs(3), client.recv_bytes()).await
        };
        let (_s, n, r) = tokio::join!(send, recv, recv_client);
        assert!(n >= super::HDR_LEN);
        assert_eq!(&r.unwrap().unwrap()[..], &b"reply"[..]);
    }

    #[tokio::test]
    async fn server_transport_send_and_recv() {
        use tokio::sync::mpsc;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(8);
        let st = UdpServerTransport::new(sock.clone(), peer_addr, [3u8; 8], rx);

        // recv_bytes returns frames pushed to the channel (as the demux would).
        tx.send(Bytes::from_static(b"from-demux")).await.unwrap();
        assert_eq!(&st.recv_bytes().await.unwrap()[..], b"from-demux");

        // send_bytes writes an enveloped datagram the raw peer can decode.
        st.set_frame_phase(FramePhase::Established);
        st.send_bytes(b"to-peer").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _from) = peer.recv_from(&mut buf).await.unwrap();
        let mut asm = FragmentAssembler::new();
        let (hdr, got) = push_datagram(&mut asm, &buf[..n]).unwrap();
        assert_eq!(hdr.cid, [3u8; 8]);
        assert_eq!(got.as_deref(), Some(&b"to-peer"[..]));
    }
}
