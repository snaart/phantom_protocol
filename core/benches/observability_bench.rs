//! Hot-path overhead microbench for `phantom_protocol::observability`.
//!
//! Measures the cost of the recording functions that get called per packet
//! on the data path:
//!
//! - `record_send(bytes, leg)` — the headline hot-path call (atomic add).
//! - `record_recv(bytes, leg)` — symmetric receive side.
//! - `record_encrypt_ns` / `record_decrypt_ns` — per-AEAD-op accounting.
//!
//! Targets on Apple M1 reference (host typical for `cargo bench`):
//!
//! - ≤ **2 ns / call** for the atomic-only path (`telemetry-otel` OFF or
//!   the no-op shim).
//! - ≤ **20 ns / call** for labeled OTel `Counter::add` once step 6+ is in
//!   (run this bench with `--features telemetry-otel` to confirm).
//!
//! Run: `cargo bench --bench observability_bench`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use phantom_protocol::observability::{Observability, ObservabilityConfig};
use phantom_protocol::transport::types::LegType;
use std::sync::Arc;

fn bench_record_send(c: &mut Criterion) {
    let obs = Observability::new(ObservabilityConfig::default());
    c.bench_function("observability.record_send", |b| {
        b.iter(|| {
            obs.record_send(black_box(1024), black_box(LegType::Tcp));
        });
    });
}

fn bench_record_send_recv_interleaved(c: &mut Criterion) {
    let obs = Observability::new(ObservabilityConfig::default());
    c.bench_function("observability.record_send_recv", |b| {
        b.iter(|| {
            obs.record_send(black_box(1024), black_box(LegType::Tcp));
            obs.record_recv(black_box(1024), black_box(LegType::Tcp));
        });
    });
}

fn bench_record_encrypt_decrypt(c: &mut Criterion) {
    let obs = Observability::new(ObservabilityConfig::default());
    c.bench_function("observability.record_encrypt_decrypt", |b| {
        b.iter(|| {
            obs.record_encrypt_ns(black_box(120));
            obs.record_decrypt_ns(black_box(110));
        });
    });
}

fn bench_record_send_8_threads(c: &mut Criterion) {
    // `Observability::new` already returns `Arc<Observability>` so it's
    // shareable across threads as-is.
    let obs: Arc<Observability> = Observability::new(ObservabilityConfig::default());
    c.bench_function("observability.record_send.8threads.contended", |b| {
        b.iter_custom(|iters| {
            use std::time::Instant;
            let n = 8usize;
            let per = (iters as usize) / n;
            let start = Instant::now();
            let mut handles = Vec::with_capacity(n);
            for _ in 0..n {
                let obs2 = obs.clone();
                handles.push(std::thread::spawn(move || {
                    for _ in 0..per {
                        obs2.record_send(black_box(1024), black_box(LegType::Tcp));
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
            start.elapsed()
        });
    });
}

fn bench_snapshot(c: &mut Criterion) {
    let obs = Observability::new(ObservabilityConfig::default());
    // Pre-populate so the snapshot has values to read.
    for _ in 0..1000 {
        obs.record_send(1024, LegType::Tcp);
        obs.record_recv(1024, LegType::Tcp);
    }
    c.bench_function("observability.snapshot", |b| {
        b.iter(|| black_box(obs.snapshot()));
    });
}

criterion_group!(
    observability_benches,
    bench_record_send,
    bench_record_send_recv_interleaved,
    bench_record_encrypt_decrypt,
    bench_record_send_8_threads,
    bench_snapshot,
);
criterion_main!(observability_benches);
