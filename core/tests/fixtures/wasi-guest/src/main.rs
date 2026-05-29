//! WASI Preview 2 guest for the `wasi_integration` host test
//! (Section B / B5 + B7).
//!
//! Reads `PHANTOM_PORT` from the environment, opens a TCP connection
//! to `127.0.0.1:PHANTOM_PORT` via `phantom_core::transport::legs::
//! wasi::WasiLeg`, sends a fixed length-prefixed payload, reads the
//! echo, and exits with status 0 on byte-equality.
//!
//! `PHANTOM_MODE` selects the drive mechanism:
//!  - unset / any other value — `futures::executor::block_on` —
//!    proves `WasiLeg`'s `SessionTransport` impl works in isolation.
//!  - `runtime` — `phantom_core::runtime::WasiRuntime::spawn` plus a
//!    `drive` / `poll_until_progress` loop. Proves the runtime + leg
//!    composition is sound end-to-end (the gap the original PR
//!    review called out).
//!
//! Exit codes:
//!  - `0` — success (stderr emits an `OK:` marker the host asserts on)
//!  - `2` — payload mismatch
//!  - `3` — I/O error in the runtime-mode future
//!  - `4` — runtime drained but task handle not finished (executor bug)
//!
//! The PhantomSession layer is not exercised — that requires a full
//! handshake which lives behind tokio. The point of this fixture is
//! to prove the two new WASI primitives (leg + runtime) work both
//! standalone and composed.

use std::net::SocketAddr;

use phantom_core::transport::legs::wasi::WasiLeg;
use phantom_core::transport::session_transport::SessionTransport;

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
        _ => run_with_block_on(addr),
    }
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

/// Composition path (B7 follow-up to the original review): exercise
/// the `WasiRuntime` + `WasiLeg` composition end-to-end. Spawns a
/// single future onto a fresh `WasiRuntime`; the future does the
/// same send/recv as `run_with_block_on` but via the runtime's
/// `Runtime::spawn` + `drive` + `poll_until_progress` loop.
fn run_with_runtime(addr: SocketAddr) {
    // `.spawn(...)` is a trait method on `Runtime`; bring the trait
    // into scope so resolution finds it on `WasiRuntime`.
    use phantom_core::runtime::{Runtime, WasiRuntime};
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
