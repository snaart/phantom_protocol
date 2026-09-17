//! Host-side integration tests for the WASI-leg surface.
//!
//! Three `#[ignore]`-gated tests, all using the same
//! `phantom-wasi-guest` fixture:
//!  1. `wasi_guest_round_trips_payload_through_wasmtime` —
//!     default mode (`futures::executor::block_on` inside the guest)
//!     exercises `WasiLeg::connect / send / recv` standalone.
//!  2. `wasi_guest_round_trips_payload_via_runtime_through_wasmtime` —
//!     `PHANTOM_MODE=runtime` exercises the
//!     `WasiRuntime::spawn` + `drive` + `poll_until_progress`
//!     composition with `WasiLeg`, so the two pieces are also
//!     tested together.
//!  3. `wasi_guest_write_to_a_host_that_never_reads_times_out` —
//!     `PHANTOM_MODE=stall` against a host that accepts and never
//!     reads: the leg's write has to give up with `Timeout` rather
//!     than block the instance forever.
//!
//! The first two:
//!  - build the `phantom-wasi-guest` fixture via `cargo build
//!    --target wasm32-wasip2` (with the same toolchain that
//!    compiled this test binary — see `env!("CARGO")` use);
//!  - stand up a native length-prefix-aware TCP echo server on a
//!    loopback OS-chosen port;
//!  - spawn `wasmtime run` with the guest, plumbing the chosen port
//!    via `PHANTOM_PORT` and granting the `inherit-network`
//!    socket capability;
//!  - assert the guest exits with status 0 and that the expected
//!    `OK:` marker appears in stderr.
//!
//! `#[ignore]`-gated: requires `wasmtime` on PATH (≥ 25) and a
//! `wasm32-wasip2` rustup target installed. CONTRIBUTING.md
//! documents the install step.

// Tests `.unwrap()` freely so failures surface as readable diagnostics; the
// disallowed-methods list in `.clippy.toml` is for production code, not the test
// harness. (Integration-test crates are their own crate and therefore do not
// inherit `core/src/lib.rs`'s `#![cfg_attr(test, allow(...))]`.)
#![allow(clippy::disallowed_methods)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Project-relative path to the wasi-guest fixture's Cargo.toml.
fn fixture_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wasi-guest/Cargo.toml")
}

/// Project-relative path to the built guest .wasm binary.
fn guest_wasm() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wasi-guest/target/wasm32-wasip2/debug/phantom-wasi-guest.wasm")
}

/// Build the wasi guest. Idempotent — re-runs are fast no-ops if
/// nothing changed. Aborts the test on build failure.
///
/// Uses `env!("CARGO")` (the cargo that built this test) so the
/// guest is compiled with the same toolchain. Falls back to bare
/// `cargo` if the env var is somehow unset (cargo always sets it).
fn build_guest() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(&cargo)
        .args([
            "build",
            "--manifest-path",
            fixture_manifest().to_str().unwrap(),
            "--target",
            "wasm32-wasip2",
        ])
        .output()
        .expect("spawn cargo for wasi-guest build");
    if !out.status.success() {
        panic!(
            "wasi-guest build failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    assert!(guest_wasm().exists(), "guest .wasm not produced");
}

/// Length-prefix-aware TCP echo: read 4-byte BE length, then `len`
/// bytes, then write the same prefix + bytes back. Closes the
/// connection after one frame.
fn echo_once(mut stream: std::net::TcpStream) {
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        return;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    if stream.read_exact(&mut payload).is_err() {
        return;
    }
    let _ = stream.write_all(&len_buf);
    let _ = stream.write_all(&payload);
    let _ = stream.flush();
}

/// Returns `true` if both `wasm32-wasip2` is installed via rustup and
/// `wasmtime` is on PATH. Print a `SKIP:` reason and return false
/// otherwise — the tests treat that as a clear skip rather than a
/// confusing compile / spawn error.
fn wasi_runtime_available() -> bool {
    let target_installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-wasip2"))
        .unwrap_or(false);
    if !target_installed {
        eprintln!(
            "SKIP: wasm32-wasip2 target not installed (run `rustup target add wasm32-wasip2`)"
        );
        return false;
    }
    if Command::new("wasmtime").arg("--version").output().is_err() {
        eprintln!("SKIP: wasmtime not on PATH (install via `brew install wasmtime` or equivalent)");
        return false;
    }
    true
}

/// How long a guest run may take before the test kills it and fails. Every
/// mode finishes in well under a second; the bound exists so a guest that
/// blocks forever — the defect the stall mode pins — fails the test instead of
/// hanging it.
const GUEST_DEADLINE: Duration = Duration::from_secs(120);

/// Shared test body: build the guest, accept its connection on a loopback
/// OS-chosen port and hand it to `serve` on a thread of its own, run the
/// guest under `wasmtime` with `PHANTOM_PORT` set (and `PHANTOM_MODE` when
/// non-empty), assert the guest exits 0 and prints `expected_marker` to
/// stderr. `serve` also receives a signal that fires once the guest has
/// exited, for a server that has to hold the connection open until then.
fn run_guest(mode: &str, expected_marker: &str, serve: fn(TcpStream, mpsc::Receiver<()>)) {
    if !wasi_runtime_available() {
        return;
    }
    build_guest();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let port = listener.local_addr().expect("local_addr").port();
    let (guest_done_tx, guest_done_rx) = mpsc::channel();
    let server_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        serve(stream, guest_done_rx);
    });

    let mut args: Vec<String> = vec![
        "run".into(),
        "-S".into(),
        "inherit-network".into(),
        "--env".into(),
        format!("PHANTOM_PORT={port}"),
    ];
    if !mode.is_empty() {
        args.push("--env".into());
        args.push(format!("PHANTOM_MODE={mode}"));
    }

    let mut child = Command::new("wasmtime")
        .args(&args)
        .arg(guest_wasm())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wasmtime");
    let started = Instant::now();
    while child.try_wait().expect("poll wasmtime").is_none() {
        if started.elapsed() > GUEST_DEADLINE {
            let _ = child.kill();
            let out = child.wait_with_output().expect("collect killed guest");
            panic!(
                "wasi guest (mode={mode:?}) was still running after {GUEST_DEADLINE:?}\n\
                 stderr:\n{}",
                String::from_utf8_lossy(&out.stderr),
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("collect guest output");

    let _ = guest_done_tx.send(());
    let _ = server_thread.join();
    assert!(
        out.status.success(),
        "wasi guest (mode={mode:?}) exited with non-zero status: {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(expected_marker),
        "expected marker {expected_marker:?} in guest stderr (mode={mode:?}); got:\n{stderr}"
    );
}

/// The round-trip modes' server: echo one frame and close.
fn serve_echo(stream: TcpStream, _guest_done: mpsc::Receiver<()>) {
    echo_once(stream);
}

/// The stall mode's server: hold the connection open, and never read it,
/// until the guest has exited.
fn serve_without_reading(stream: TcpStream, guest_done: mpsc::Receiver<()>) {
    let _ = guest_done.recv();
    drop(stream);
}

/// Proves `WasiLeg::connect / send / recv` work via
/// `futures::executor::block_on` (the simplest possible driver).
#[test]
#[ignore]
fn wasi_guest_round_trips_payload_through_wasmtime() {
    run_guest("", "OK: round-tripped", serve_echo);
}

/// Proves the `WasiRuntime` + `WasiLeg` composition works
/// end-to-end, so their joint use has integration coverage.
#[test]
#[ignore]
fn wasi_guest_round_trips_payload_via_runtime_through_wasmtime() {
    run_guest("runtime", "OK: runtime-driven round-trip", serve_echo);
}

/// Proves a write to a host that never reads gives up with `Timeout`
/// instead of blocking the instance forever, and that nothing is written
/// after it.
#[test]
#[ignore]
fn wasi_guest_write_to_a_host_that_never_reads_times_out() {
    run_guest(
        "stall",
        "OK: a write the host never read failed with Timeout",
        serve_without_reading,
    );
}
