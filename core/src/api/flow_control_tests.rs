//! Receive-window auto-tuning, measured end to end (test-only).
//!
//! A credit window of `W` bytes whose credit returns one round trip after the data was
//! consumed is a hard rate ceiling of `W / RTT`, whatever congestion control decides. With
//! `W` fixed at 64 KiB that is 2.6 Mbit/s on a 200 ms path — under a third of what the paths
//! this transport targets actually carry — so on a long path the limiter was flow control,
//! not the network, and no amount of congestion-control work could move it.
//!
//! These tests measure that ceiling directly. They reuse [`Link`] from the full-duplex suite
//! — one direction of a real path, a FIFO delay line with a propagation delay and a
//! serialisation rate — because the contention has to be real: over a loopback transport the
//! window is never the binding constraint and the measurement proves nothing. Here the link
//! is deliberately set several times faster than a fixed 64 KiB window permits, so anything
//! above that ceiling can only come from the window having moved.
//!
//! The module is declared `#[cfg(test)]` in `api/mod.rs`, so it carries no inner
//! `#![cfg(test)]` of its own.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use crate::api::full_duplex_tests::{establish_counted, shutdown, spawn_saturating_sender};
use crate::api::session::PhantomSession;
use crate::transport::stream::INITIAL_STREAM_WINDOW;

/// One-way propagation delay, so the RTT is 200 ms — the order of the real-WAN path the
/// defect was measured on, and long enough that a 64 KiB window is unambiguously the
/// binding constraint.
const ONE_WAY: Duration = Duration::from_millis(100);
/// Serialisation rate of each direction. 2 MiB/s ≈ 16.8 Mbit/s, deliberately ~6× the rate a
/// fixed 64 KiB window allows on this path: the link must not be what the test measures.
const LINK_BYTES_PER_SEC: u64 = 2 * 1024 * 1024;
/// Downstream application frame size — one `send()`, one MTU-sized segment.
const FRAME: usize = 1024;

/// The sustained rate a fixed [`INITIAL_STREAM_WINDOW`] permits on this path: one window per
/// round trip, 320 KiB/s. Every assertion below is stated against this number rather than an
/// absolute throughput, so the test says what it means on a loaded runner.
const FIXED_WINDOW_CEILING_BPS: u64 =
    INITIAL_STREAM_WINDOW as u64 * 1000 / (2 * ONE_WAY.as_millis() as u64);

/// Long enough for both ladders to climb: congestion control has to find the link rate, and
/// the receive window has to walk up from 64 KiB, one doubling per round-trip-length
/// measurement interval, until it stops being the binding constraint on this 2 MiB/s link.
const WARMUP: Duration = Duration::from_millis(3000);
/// Measurement window. Long enough that the ramp inside it is not what is being measured.
const WINDOW: Duration = Duration::from_millis(3000);

/// Drain `session.recv()` until `stop` is set, accumulating received bytes so a caller can
/// sample the counter at phase boundaries. A prompt reader is the precondition of the whole
/// feature: this is the application demonstrating the consumption the window is granted for.
fn spawn_prompt_receiver(
    session: Arc<PhantomSession>,
    stop: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while !stop.load(Ordering::Relaxed) {
            match timeout(Duration::from_millis(500), session.recv()).await {
                Ok(Ok(bytes)) => {
                    counter.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                }
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }
    })
}

/// **The throughput regression.** A stream whose receiver consumes promptly must sustain a
/// rate above what a fixed 64 KiB window permits on this path. Before receive-window
/// auto-tuning it could not: the window returned 64 KiB of credit per round trip and the
/// download sat pinned at ~320 KiB/s on a link carrying six times that, with congestion
/// control's window never becoming the binding constraint at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_promptly_drained_download_beats_the_fixed_window_rate_ceiling() {
    let (client, server, _) = establish_counted(ONE_WAY, LINK_BYTES_PER_SEC).await;

    let stop_down = Arc::new(AtomicBool::new(false));
    let stop_rx = Arc::new(AtomicBool::new(false));
    let downloaded = Arc::new(AtomicU64::new(0));

    let downloader = spawn_saturating_sender(server.clone(), stop_down.clone(), FRAME);
    let client_rx = spawn_prompt_receiver(client.clone(), stop_rx.clone(), downloaded.clone());

    tokio::time::sleep(WARMUP).await;
    let start = downloaded.load(Ordering::Relaxed);
    tokio::time::sleep(WINDOW).await;
    let moved = downloaded.load(Ordering::Relaxed) - start;

    stop_down.store(true, Ordering::Relaxed);
    stop_rx.store(true, Ordering::Relaxed);
    let _ = timeout(Duration::from_secs(15), downloader).await;
    let _ = timeout(Duration::from_secs(5), client_rx).await;

    let rate = moved * 1000 / WINDOW.as_millis() as u64;
    eprintln!(
        "download: {moved} B in {} ms = {rate} B/s; fixed-window ceiling on this path is \
         {FIXED_WINDOW_CEILING_BPS} B/s ({:.2}×), link rate {LINK_BYTES_PER_SEC} B/s",
        WINDOW.as_millis(),
        rate as f64 / FIXED_WINDOW_CEILING_BPS as f64,
    );

    // Measured on this harness: ~320 KB/s before (1.0× the ceiling, i.e. exactly window-
    // limited), ~1.9 MB/s after (~6×, i.e. link-limited). 1.5× sits between those by a wide
    // margin in both directions and does not depend on the runner being fast.
    assert!(
        rate > FIXED_WINDOW_CEILING_BPS * 3 / 2,
        "the download is still pinned to the fixed-window rate ceiling: {rate} B/s vs a \
         {FIXED_WINDOW_CEILING_BPS} B/s ceiling, on a link carrying {LINK_BYTES_PER_SEC} B/s"
    );
}

/// **The safety direction, end to end.** The advertised window is a memory-safety mechanism
/// first: it bounds how much an unacknowledged peer can make this side buffer. Growing it is
/// therefore tied to demonstrated *application consumption* and never to arrival — so a
/// receiver whose application never reads must stall its peer, and must stall it at
/// substantially the same point as before auto-tuning existed.
///
/// What bounds the number below: the initial 64 KiB window, plus the doublings the bounded
/// delivery queue in front of `recv()` can pay for as it fills (the queue absorbs a few
/// hundred KiB whether or not the application ever reads it — that is true of this
/// implementation with or without auto-tuning), plus handshake and framing. It is emphatically
/// *not* the megabyte the application handed to `send()`: most of that is still sitting in the
/// stream's send buffer, which is why this measures the wire and not the sender's API.
///
/// Note what does **not** appear in that list:
/// [`crate::transport::stream::MAX_RECV_WINDOW`]. The queue transient is a fixed number of
/// bytes — the 256-slot `recv()` channel — so it pays for a fixed number of doublings no
/// matter how many rungs the ceiling above it offers. That is the property worth pinning: a
/// ceiling is not an allowance, and this test's bound is therefore allowed to stay where it
/// was when the ceiling was half its present size.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_that_never_reads_stalls_the_sender() {
    let (client, server, server_wire) = establish_counted(ONE_WAY, LINK_BYTES_PER_SEC).await;

    // The client never calls recv(). Nothing is consumed, so nothing may be granted.
    let stop_down = Arc::new(AtomicBool::new(false));
    let downloader = spawn_saturating_sender(server.clone(), stop_down.clone(), FRAME);

    // Six seconds is thirty round trips: an unconstrained sender would have put ~12 MiB on
    // this link by now.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let on_wire = server_wire.load(Ordering::Relaxed);
    stop_down.store(true, Ordering::Relaxed);
    let _ = timeout(Duration::from_secs(15), downloader).await;

    eprintln!(
        "non-reading receiver: server put {on_wire} B on the wire in 6 s; an unconstrained \
         sender would have put {} B",
        LINK_BYTES_PER_SEC * 6
    );

    assert!(
        on_wire > 32 * 1024,
        "the sender transmitted almost nothing ({on_wire} B) — the harness, not flow \
         control, is what stopped it"
    );
    // Both sides of this bound are measured on this harness rather than reasoned about.
    // Honest, over sixteen runs: 413–552 KB, quantised — fifteen runs land at 413–419 KB
    // (two doublings bought by the queue transient) and one at 552 KB, the third doubling
    // the transient can occasionally afford. Failing, with the consumption test removed so
    // the tuner grows on arrival: 821–823 KB over three runs, the next rung up; and with the
    // window removed entirely the link would carry 12 MiB. 640 KiB sits between the two
    // measured populations — 1.19× above the worst honest run, 1.25× below the cheapest way
    // to fail — and is unchanged from before the ceiling moved, which is the point: raising
    // the ceiling added rungs the queue transient still cannot pay for.
    assert!(
        on_wire < 640 * 1024,
        "a receiver whose application never read a byte let its peer transmit {on_wire} B — \
         the window grew on arrival rather than on consumption"
    );

    shutdown(&client, &server).await;
}
