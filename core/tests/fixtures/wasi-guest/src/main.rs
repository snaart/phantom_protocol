//! WASI Preview 2 guest for the `wasi_integration` host test (B5).
//!
//! Reads `PHANTOM_PORT` from the environment, opens a TCP connection
//! to `127.0.0.1:PHANTOM_PORT` via `phantom_core::transport::legs::
//! wasi::WasiLeg`, sends a fixed length-prefixed payload, reads the
//! echo, and exits with status 0 on byte-equality. Anything else
//! aborts with a non-zero exit so the host test observes failure.
//!
//! The PhantomSession layer is **not** exercised by this guest —
//! that requires fips-disabled crypto + the full handshake state
//! machine, which lives behind tokio on the default build. The
//! purpose of B5 is to prove `WasiLeg::connect / send / recv` work
//! over a real WASI host; full session integration ships as a
//! follow-up once `connect_with_transport_with_runtime` is wired
//! against `WasiRuntime`.

use std::net::SocketAddr;

use phantom_core::transport::legs::wasi::WasiLeg;
use phantom_core::api::session::SessionTransport;

const PAYLOAD: &[u8] = b"phantom-wasi-guest-roundtrip-v1";

fn main() {
    let port: u16 = std::env::var("PHANTOM_PORT")
        .expect("PHANTOM_PORT env not set")
        .parse()
        .expect("PHANTOM_PORT not a valid u16");
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("failed to parse 127.0.0.1 socket address");

    let leg = WasiLeg::connect(addr).expect("WasiLeg::connect");

    // Block on send + recv. `SessionTransport`'s async fns under
    // `--features wasi-leg` use WASI blocking I/O internally, so the
    // returned futures resolve synchronously when polled from the
    // current task.
    let send_fut = leg.send_bytes(PAYLOAD);
    futures::executor::block_on(send_fut).expect("send_bytes");

    let recv_fut = leg.recv_bytes();
    let echo = futures::executor::block_on(recv_fut).expect("recv_bytes");

    if &echo[..] != PAYLOAD {
        eprintln!(
            "MISMATCH: expected {:?}, got {:?}",
            hex::encode(PAYLOAD),
            hex::encode(&echo[..]),
        );
        std::process::exit(2);
    }
    eprintln!("OK: round-tripped {} bytes through WasiLeg", PAYLOAD.len());
}
