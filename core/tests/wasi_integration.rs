//! Host-side integration tests for the WASI-leg surface
//! (Section B / B5 + B7 of the pre-1.0 deferred-followups plan).
//!
//! Two `#[ignore]`-gated tests, both using the same
//! `phantom-wasi-guest` fixture:
//!  1. `wasi_guest_round_trips_payload_through_wasmtime` —
//!     default mode (`futures::executor::block_on` inside the guest)
//!     exercises `WasiLeg::connect / send / recv` standalone.
//!  2. `wasi_guest_round_trips_payload_via_runtime_through_wasmtime` —
//!     `PHANTOM_MODE=runtime` exercises the
//!     `WasiRuntime::spawn` + `drive` + `poll_until_progress`
//!     composition with `WasiLeg`. Added in B7 to close the
//!     review-time gap that the two pieces were never tested
//!     together.
//!
//! Both:
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

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

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

/// Shared test body: build the guest, spin up an echo server on a
/// loopback OS-chosen port, run the guest under `wasmtime` with
/// `PHANTOM_PORT` set (and `PHANTOM_MODE` when non-empty), assert
/// the guest exits 0 and prints `expected_marker` to stderr.
fn run_guest_round_trip(mode: &str, expected_marker: &str) {
    if !wasi_runtime_available() {
        return;
    }
    build_guest();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo server");
    let port = listener.local_addr().expect("local_addr").port();
    let server_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        echo_once(stream);
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

    let out = Command::new("wasmtime")
        .args(&args)
        .arg(guest_wasm())
        .output()
        .expect("spawn wasmtime");

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

/// B5 — proves `WasiLeg::connect / send / recv` work via
/// `futures::executor::block_on` (the simplest possible driver).
#[test]
#[ignore]
fn wasi_guest_round_trips_payload_through_wasmtime() {
    run_guest_round_trip("", "OK: round-tripped");
}

/// B7 — proves the `WasiRuntime` + `WasiLeg` composition works
/// end-to-end. Closes the review gap that the two pieces shipped
/// without any integration coverage of their joint use.
#[test]
#[ignore]
fn wasi_guest_round_trips_payload_via_runtime_through_wasmtime() {
    run_guest_round_trip("runtime", "OK: runtime-driven round-trip");
}
