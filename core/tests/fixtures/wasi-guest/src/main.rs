//! WASI Preview 2 guest for the `wasi_integration` host test.
//!
//! Reads `PHANTOM_PORT` from the environment, opens a TCP connection
//! to `127.0.0.1:PHANTOM_PORT` via `phantom_protocol::transport::legs::
//! wasi::WasiLeg`, sends a fixed length-prefixed payload, reads the
//! echo, and exits with status 0 on byte-equality.
//!
//! `PHANTOM_MODE` selects the drive mechanism:
//!  - unset / any other value — `futures::executor::block_on` —
//!    proves `WasiLeg`'s `SessionTransport` impl works in isolation.
//!  - `runtime` — `phantom_protocol::runtime::WasiRuntime::spawn` plus a
//!    `drive` / `poll_until_progress` loop. Proves the runtime + leg
//!    composition is sound end-to-end (the gap the original PR
//!    review called out).
//!  - `stall` — the host accepts the connection and never reads it. The
//!    guest writes until a write fails, and that failure has to be the
//!    leg's `Timeout` rather than a wait that never ends; the write after
//!    it has to be refused the same way.
//!
//! Exit codes:
//!  - `0` — success (stderr emits an `OK:` marker the host asserts on)
//!  - `2` — payload mismatch
//!  - `3` — I/O error in the runtime-mode future
//!  - `4` — runtime drained but task handle not finished (executor bug)
//!  - `5` — stall mode: every write succeeded, so nothing was ever stalled
//!  - `6` — stall mode: a write failed, but not with `Timeout`
//!  - `7` — stall mode: a write after the stall was not refused with `Timeout`
//!
//! The PhantomSession layer is not exercised — that requires a full
//! handshake which lives behind tokio. The point of this fixture is
//! to prove the two new WASI primitives (leg + runtime) work both
//! standalone and composed.

use std::net::SocketAddr;

use phantom_protocol::transport::legs::wasi::WasiLeg;
use phantom_protocol::transport::session_transport::SessionTransport;

const PAYLOAD: &[u8] = b"phantom-wasi-guest-roundtrip-v1";

fn main() {
    let port: u16 = std::env::var("PHANTOM_PORT")
        .expect("PHANTOM_PORT env not set")
        .parse()
        .expect("PHANTOM_PORT not a valid u16");
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("failed to parse 127.0.0.1 socket address");

    let mode = std::env::var("PHANTOM_MODE").unwrap_or_default();
    match mode.as_str() {
        "runtime" => run_with_runtime(addr),
        "stall" => run_against_a_peer_that_never_reads(addr),
        _ => run_with_block_on(addr),
    }
}

/// Stall path: the host never reads, so the socket buffers fill and a write
/// has to wait on it. The leg must give up on that write with `Timeout` once
/// it has made no progress for its deadline, instead of blocking the instance
/// forever, and must then refuse the next write rather than append it to the
/// frame the stalled one cut off.
fn run_against_a_peer_that_never_reads(addr: SocketAddr) {
    use phantom_protocol::CoreError;
    use std::time::Duration;

    /// 64 MiB in all: far more than loopback socket buffers hold, so the
    /// writes cannot all complete without the host reading. The frames stay
    /// at 4 KiB so the run also means something against a leg that writes
    /// through the blocking stream call, which takes at most 4096 bytes.
    const MAX_FRAMES: usize = 16 * 1024;

    let leg = WasiLeg::connect(addr)
        .expect("WasiLeg::connect (stall mode)")
        .with_write_stall_timeout(Duration::from_millis(500));
    let frame = vec![0xA5_u8; 4 * 1024];
    let mut sent = 0usize;
    let failure = loop {
        match futures::executor::block_on(leg.send_bytes(&frame)) {
            Ok(()) if sent < MAX_FRAMES => sent += 1,
            Ok(()) => {
                eprintln!("NEVER STALLED: {sent} frames of 4 KiB all went out");
                std::process::exit(5);
            }
            Err(e) => break e,
        }
    };
    if !matches!(failure, CoreError::Timeout) {
        eprintln!("WRONG ERROR: the stalled write failed with {failure:?}");
        std::process::exit(6);
    }
    match futures::executor::block_on(leg.send_bytes(b"after the stall")) {
        Err(CoreError::Timeout) => {}
        other => {
            eprintln!("NOT REFUSED: the write after the stall gave {other:?}");
            std::process::exit(7);
        }
    }
    eprintln!("OK: a write the host never read failed with Timeout after {sent} frames");
}

/// Default path: drive `WasiLeg` via `futures::executor::block_on`.
/// `WasiLeg`'s `SessionTransport` futures resolve synchronously
/// because the WASI Preview 2 `blocking_*` stream calls park the
/// instance host-side, so no real executor work is needed.
fn run_with_block_on(addr: SocketAddr) {
    let leg = WasiLeg::connect(addr).expect("WasiLeg::connect (block_on mode)");

    futures::executor::block_on(leg.send_bytes(PAYLOAD)).expect("send_bytes");
    let echo = futures::executor::block_on(leg.recv_bytes()).expect("recv_bytes");

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

/// Composition path: exercise the `WasiRuntime` + `WasiLeg`
/// composition end-to-end. Spawns a single future onto a fresh
/// `WasiRuntime`; the future does the same send/recv as
/// `run_with_block_on` but via the runtime's `Runtime::spawn` +
/// `drive` + `poll_until_progress` loop.
fn run_with_runtime(addr: SocketAddr) {
    // `.spawn(...)` is a trait method on `Runtime`; bring the trait
    // into scope so resolution finds it on `WasiRuntime`.
    use phantom_protocol::runtime::{Runtime, WasiRuntime};
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let rt = WasiRuntime::new();
    let leg = Arc::new(WasiLeg::connect(addr).expect("WasiLeg::connect (runtime mode)"));

    // 0 = task never ran to completion; 1 = round-trip ok;
    // 2 = payload mismatch; 3 = I/O error.
    let outcome = Arc::new(AtomicU8::new(0));

    let leg_task = Arc::clone(&leg);
    let outcome_task = Arc::clone(&outcome);
    let handle = rt.spawn(Box::pin(async move {
        if leg_task.send_bytes(PAYLOAD).await.is_err() {
            outcome_task.store(3, Ordering::SeqCst);
            return;
        }
        match leg_task.recv_bytes().await {
            Err(_) => outcome_task.store(3, Ordering::SeqCst),
            Ok(echo) => {
                if &echo[..] == PAYLOAD {
                    outcome_task.store(1, Ordering::SeqCst);
                } else {
                    outcome_task.store(2, Ordering::SeqCst);
                }
            }
        }
    }));

    // Drive until the spawned task drains out of the queue. WASI
    // `blocking_*` calls inside the future cause `drive()` to do the
    // real work synchronously; `poll_until_progress` is the watchdog
    // that keeps the loop from spin-busy-waiting on a future that
    // returns `Pending` without registering a Pollable.
    while rt.tasks_pending() > 0 {
        rt.drive();
        rt.poll_until_progress(Duration::from_millis(100));
    }
    if !handle.is_finished() {
        eprintln!("BUG: runtime drained but handle reports not finished");
        std::process::exit(4);
    }

    match outcome.load(Ordering::SeqCst) {
        1 => eprintln!(
            "OK: runtime-driven round-trip of {} bytes through WasiLeg",
            PAYLOAD.len()
        ),
        2 => {
            eprintln!("MISMATCH (runtime mode)");
            std::process::exit(2);
        }
        3 => {
            eprintln!("IO ERROR (runtime mode)");
            std::process::exit(3);
        }
        _ => {
            eprintln!("BUG: outcome flag never set");
            std::process::exit(4);
        }
    }
}
