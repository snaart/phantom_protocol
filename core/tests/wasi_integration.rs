//! Host-side integration tests for the WASI-leg surface
//! (Section B / B5 of the pre-1.0 deferred-followups plan).
//!
//! The test:
//!  1. Builds the `phantom-wasi-guest` fixture (a WASI Preview 2
//!     binary that uses `phantom_core::transport::legs::wasi::
//!     WasiLeg`) via `cargo build --target wasm32-wasip2`.
//!  2. Stands up a native length-prefix-aware TCP echo server on a
//!     loopback OS-chosen port.
//!  3. Spawns `wasmtime run` with the guest, plumbing the chosen
//!     port via `PHANTOM_PORT` env, and grants the guest the
//!     `inherit-network` socket capability.
//!  4. Asserts the guest exits with status 0 (the guest itself
//!     asserts byte-equality between sent and echoed payload and
//!     exits 2 on mismatch).
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
fn build_guest() {
    let out = Command::new("cargo")
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

#[test]
#[ignore]
fn wasi_guest_round_trips_payload_through_wasmtime() {
    // Step 1: build the guest. Skip the rest if wasm32-wasip2 isn't
    // installed — surface that as a clear test skip rather than a
    // confusing compile error.
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-wasip2"))
        .unwrap_or(false);
    if !installed {
        eprintln!(
            "SKIP: wasm32-wasip2 target not installed (run `rustup target add wasm32-wasip2`)"
        );
        return;
    }
    if Command::new("wasmtime").arg("--version").output().is_err() {
        eprintln!("SKIP: wasmtime not on PATH (install via `brew install wasmtime` or equivalent)");
        return;
    }
    build_guest();

    // Step 2: native echo server on loopback.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo server");
    let port = listener.local_addr().expect("local_addr").port();
    let server_thread = thread::spawn(move || {
        // Accept exactly one connection; the guest sends one frame
        // and exits.
        let (stream, _) = listener.accept().expect("accept");
        echo_once(stream);
    });

    // Step 3: spawn wasmtime with the guest.
    let out = Command::new("wasmtime")
        .args([
            "run",
            "-S",
            "inherit-network",
            "--env",
            &format!("PHANTOM_PORT={port}"),
        ])
        .arg(guest_wasm())
        .output()
        .expect("spawn wasmtime");

    // Step 4: assert success.
    let _ = server_thread.join();
    assert!(
        out.status.success(),
        "wasi guest exited with non-zero status: {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("OK: round-tripped"),
        "expected success marker in guest stderr; got:\n{stderr}"
    );
}
