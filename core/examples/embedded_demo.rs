//! Host-side demo of [`EmbeddedLeg`] over a mock UART-style byte duplex.
//!
//! Run:
//!
//! ```text
//! cargo run --manifest-path core/Cargo.toml --features embedded --example embedded_demo
//! ```
//!
//! Wires two `EmbeddedLeg` instances together via a cross-connected in-memory
//! byte pipe (standing in for a real UART / USB-CDC pair), runs the full hybrid
//! PQ handshake (X25519 + ML-KEM-768 KEM, Ed25519 + ML-DSA-65 signatures),
//! exchanges one encrypted request/reply, and prints handshake-vs-payload
//! byte counts so an operator can see the protocol in action.

use core::convert::Infallible;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use embedded_io_async::{Read, Write};
use phantom_core::api::session::{ConnectionState, PhantomSession, SessionTransport};
use phantom_core::transport::handshake::{ClientHello, HandshakeResponse, HandshakeServer};
use phantom_core::transport::legs::embedded::EmbeddedLeg;
use phantom_core::transport::session::Session;
use phantom_core::transport::types::{
    PacketFlags, PacketHeader, PhantomPacket, SessionId, StreamId,
};
use phantom_core::CoreError;
use tokio::sync::{Mutex as TokioMutex, Notify};
use tokio::time::timeout;

const BUF: usize = 16384;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

// ── Mock UART duplex over `embedded-io-async` ──────────────────────────────
//
// `duplex_pair()` returns two halves cross-wired so A's writer feeds B's
// reader and vice versa. The atomic byte counter on each `MockWriter` powers
// the on-wire byte accounting printed below.

struct Pipe {
    buf: VecDeque<u8>,
    closed: bool,
}

struct MockReader {
    read_from: Arc<TokioMutex<Pipe>>,
    notify: Arc<Notify>,
}

struct MockWriter {
    write_to: Arc<TokioMutex<Pipe>>,
    notify: Arc<Notify>,
    bytes_out: Arc<AtomicUsize>,
}

fn pipe() -> Arc<TokioMutex<Pipe>> {
    Arc::new(TokioMutex::new(Pipe {
        buf: VecDeque::new(),
        closed: false,
    }))
}

fn duplex_pair() -> (
    (MockReader, MockWriter, Arc<AtomicUsize>),
    (MockReader, MockWriter, Arc<AtomicUsize>),
) {
    let (ab, ba) = (pipe(), pipe());
    let (n_ab, n_ba) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let (a_out, b_out) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    (
        (
            MockReader {
                read_from: ba.clone(),
                notify: n_ba.clone(),
            },
            MockWriter {
                write_to: ab.clone(),
                notify: n_ab.clone(),
                bytes_out: a_out.clone(),
            },
            a_out,
        ),
        (
            MockReader {
                read_from: ab,
                notify: n_ab,
            },
            MockWriter {
                write_to: ba,
                notify: n_ba,
                bytes_out: b_out.clone(),
            },
            b_out,
        ),
    )
}

impl embedded_io_async::ErrorType for MockReader {
    type Error = Infallible;
}
impl embedded_io_async::ErrorType for MockWriter {
    type Error = Infallible;
}

impl Read for MockReader {
    async fn read(&mut self, out: &mut [u8]) -> Result<usize, Infallible> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            // Arm the notified BEFORE we lock+check so a notify between the
            // unlock and the await is not lost.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut p = self.read_from.lock().await;
                if !p.buf.is_empty() {
                    let n = out.len().min(p.buf.len());
                    for slot in out.iter_mut().take(n) {
                        *slot = p.buf.pop_front().expect("checked non-empty");
                    }
                    return Ok(n);
                }
                if p.closed {
                    return Ok(0);
                }
            }
            notified.await;
        }
    }
}

impl Write for MockWriter {
    async fn write(&mut self, data: &[u8]) -> Result<usize, Infallible> {
        let mut p = self.write_to.lock().await;
        p.buf.extend(data.iter().copied());
        drop(p);
        self.bytes_out.fetch_add(data.len(), Ordering::Relaxed);
        self.notify.notify_waiters();
        Ok(data.len())
    }
}

// `SessionTransport` for the demo leg. The `impl_embedded_session_transport!`
// macro would normally collapse this to one line, but it references the
// crate-private `errors` module and the orphan rule blocks `impl ForeignTrait
// for ForeignType<…>` from outside the defining crate. A local newtype
// sidesteps both — production embedded crates that depend on `phantom_core`
// can still use the macro one-liner.
struct DemoLeg(EmbeddedLeg<MockReader, MockWriter, BUF>);

impl SessionTransport for DemoLeg {
    fn send_bytes(
        &self,
        data: &[u8],
    ) -> impl core::future::Future<Output = Result<(), CoreError>> + Send {
        self.0.send_frame(data)
    }
    fn recv_bytes(&self) -> impl core::future::Future<Output = Result<Bytes, CoreError>> + Send {
        self.0.recv_frame()
    }
}

// ── Server-side encrypt/decrypt helpers ────────────────────────────────────

fn decrypt_incoming(sess: &Session, bytes: &[u8]) -> Vec<u8> {
    let p = alkahest::deserialize::<PhantomPacket, PhantomPacket>(bytes)
        .expect("deserialize PhantomPacket");
    sess.decrypt_packet(&p.header, &p.payload).expect("decrypt")
}

fn encrypt_outgoing(
    sess: &Session,
    sid: SessionId,
    stream: StreamId,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let flags = PacketFlags::new(PacketFlags::RELIABLE | PacketFlags::ENCRYPTED);
    let header = PacketHeader::new(sid, stream, seq, flags).with_epoch(sess.current_epoch());
    let ct = sess.encrypt_packet(&header, payload).expect("encrypt");
    let packet = PhantomPacket::new(header, ct);
    let mut buf = Vec::new();
    let (size, _) = alkahest::serialize_to_vec::<PhantomPacket, _>(&packet, &mut buf);
    buf[..size].to_vec()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Wire two EmbeddedLegs together over a mock UART duplex.
    let ((c_r, c_w, c_out), (s_r, s_w, s_out)) = duplex_pair();
    let client_leg = DemoLeg(EmbeddedLeg::new(c_r, c_w));
    let server_leg: EmbeddedLeg<MockReader, MockWriter, BUF> = EmbeddedLeg::new(s_r, s_w);

    // 2. Server long-lived hybrid signing key + pinning hex preview.
    println!("Generating server hybrid signing key (Ed25519 + ML-DSA-65)\u{2026}");
    let server_hs = HandshakeServer::new()?;
    let pinned_key = server_hs.verifying_key().clone();
    let pk_bytes = pinned_key.to_bytes();
    let pk_hex: String = pk_bytes
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect();
    println!(
        "Pinning client to server verifying key ({}\u{2026}, {} bytes total)\u{2026}",
        pk_hex,
        pk_bytes.len()
    );

    // 3. Server task — drive the handshake by hand, then echo one message.
    let server_handle = tokio::spawn(async move {
        let client_ip = "127.0.0.1".parse().expect("loopback IP");

        let raw = timeout(IO_TIMEOUT, server_leg.recv_frame())
            .await
            .expect("recv ClientHello timed out")
            .expect("recv ClientHello");
        let mut client_hello = borsh::from_slice::<ClientHello>(&raw).expect("parse ClientHello");

        // The DoS gate may demand a stateless cookie / PoW on first contact;
        // the client transparently re-sends on `HelloRetryRequest`.
        let server_session = loop {
            match server_hs.process_client_hello(&client_hello, 0, client_ip) {
                HandshakeResponse::Success(server_hello, session, _) => {
                    let bytes = borsh::to_vec(&server_hello).expect("serialize ServerHello");
                    timeout(IO_TIMEOUT, server_leg.send_frame(&bytes))
                        .await
                        .expect("send ServerHello timed out")
                        .expect("send ServerHello");
                    break session;
                }
                HandshakeResponse::Retry(retry) => {
                    let bytes = borsh::to_vec(&retry).expect("serialize HelloRetryRequest");
                    timeout(IO_TIMEOUT, server_leg.send_frame(&bytes))
                        .await
                        .expect("send retry timed out")
                        .expect("send retry");
                    let next = timeout(IO_TIMEOUT, server_leg.recv_frame())
                        .await
                        .expect("recv retried hello timed out")
                        .expect("recv retried hello");
                    client_hello =
                        borsh::from_slice::<ClientHello>(&next).expect("parse retried ClientHello");
                    continue;
                }
                HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
            }
        };
        let session_id = *server_session.id();

        let req_frame = timeout(IO_TIMEOUT, server_leg.recv_frame())
            .await
            .expect("recv request timed out")
            .expect("recv request");
        let req = decrypt_incoming(&server_session, &req_frame);
        println!(
            "Server received encrypted payload; decrypted: {:?}",
            String::from_utf8_lossy(&req)
        );

        let reply_msg = b"reply from server";
        println!(
            "Server replying with: {:?}",
            String::from_utf8_lossy(reply_msg)
        );
        let reply = encrypt_outgoing(&server_session, session_id, 1, 1, reply_msg);
        timeout(IO_TIMEOUT, server_leg.send_frame(&reply))
            .await
            .expect("send reply timed out")
            .expect("send reply");
    });

    // 4. Client — `connect_with_transport` spawns the handshake task in the
    //    background; poll `connection_state` until it reaches `Connected`.
    let session = PhantomSession::connect_with_transport("embedded-demo:0", client_leg, pinned_key);

    let mut ok = false;
    for _ in 0..250 {
        if session.connection_state() == ConnectionState::Connected {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if !ok {
        return Err("client failed to reach Connected within 5s".into());
    }
    let hs_c_out = c_out.load(Ordering::Relaxed);
    let hs_s_out = s_out.load(Ordering::Relaxed);
    println!(
        "Handshake bytes exchanged: ClientHello={} bytes, ServerHello={} bytes",
        hs_c_out, hs_s_out
    );

    // 5. Encrypted application exchange.
    let req_msg = b"hello from client over EmbeddedLeg";
    println!(
        "Sending encrypted payload: {:?}",
        String::from_utf8_lossy(req_msg)
    );
    timeout(IO_TIMEOUT, session.send(req_msg.to_vec()))
        .await
        .expect("client send timed out")?;

    let reply = timeout(IO_TIMEOUT, session.recv())
        .await
        .expect("client recv timed out")?;
    println!(
        "Client received decrypted reply: {:?}",
        String::from_utf8_lossy(&reply)
    );

    println!(
        "Encrypted payload bytes on the wire: client\u{2192}server={}, server\u{2192}client={}",
        c_out.load(Ordering::Relaxed) - hs_c_out,
        s_out.load(Ordering::Relaxed) - hs_s_out
    );

    // 6. Clean shutdown.
    timeout(IO_TIMEOUT, server_handle)
        .await
        .expect("server task timed out")?;
    timeout(IO_TIMEOUT, session.disconnect())
        .await
        .expect("disconnect timed out")?;
    println!("Demo complete.");
    Ok(())
}
