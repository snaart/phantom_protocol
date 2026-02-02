//! Focused encryption-only benchmark.
//! Measures raw ring AES-256-GCM speed with zero allocation overhead.

use std::time::Instant;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║      CRYPTO MICROBENCHMARK: ring AES-GCM vs ChaCha20        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let key_bytes = [0xABu8; 32];

    println!("--- AES-256-GCM (ring, should use ARM AES intrinsics) ---");
    bench_aead(&AES_256_GCM, &key_bytes);

    println!();
    println!("--- ChaCha20-Poly1305 (ring) ---");
    bench_aead(&CHACHA20_POLY1305, &key_bytes);

    println!();
    println!("--- Allocation overhead comparison ---");
    bench_alloc_overhead();
}

fn bench_aead(algo: &'static ring::aead::Algorithm, key_bytes: &[u8; 32]) {
    let uk = UnboundKey::new(algo, key_bytes).unwrap();
    let key = LessSafeKey::new(uk);

    for &size in &[64, 1024, 16384, 65536, 262144, 1048576] {
        // Pre-allocate: plaintext + space for 16-byte tag
        let mut buf = vec![0xCDu8; size + 16];
        let tag_len = algo.tag_len();

        let iters: usize = if size <= 1024 { 1_000_000 } else if size <= 65536 { 200_000 } else { 50_000 };

        let start = Instant::now();
        let mut counter: u64 = 0;
        for _ in 0..iters {
            // Reset buffer to "plaintext" state (keep allocation!)
            // Only write tag area as 0, rest stays as-is — doesn't affect encryption speed
            buf.truncate(size);
            // Space for tag
            buf.resize(size + tag_len, 0);

            // Build nonce
            let mut n = [0u8; 12];
            n[4..].copy_from_slice(&counter.to_be_bytes());
            counter += 1;
            let nonce = Nonce::assume_unique_for_key(n);

            // IN-PLACE encrypt (zero allocation)
            let _ = key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut buf[..size]).unwrap();
        }
        let elapsed = start.elapsed();

        let total_mb = (size as f64 * iters as f64) / (1024.0 * 1024.0);
        let throughput = total_mb / elapsed.as_secs_f64();

        println!(
            "  {:>8}: {:>10.1} MiB/s  ({:.3} ms / {} iters)",
            format_size(size),
            throughput,
            elapsed.as_secs_f64() * 1000.0,
            iters,
        );
    }
}

fn bench_alloc_overhead() {
    let size = 65536usize;
    let iters = 200_000;

    // Measure: clone a vec (simulating per-packet allocation)
    let data = vec![0xABu8; size];
    let start = Instant::now();
    for _ in 0..iters {
        let v = data.clone();
        std::hint::black_box(v);
    }
    let alloc_elapsed = start.elapsed();
    let alloc_mb = (size as f64 * iters as f64) / (1024.0 * 1024.0);
    let alloc_tput = alloc_mb / alloc_elapsed.as_secs_f64();

    // Measure: same but with in-place write to pre-allocated buf
    let mut buf = vec![0u8; size];
    let start2 = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&data);
        std::hint::black_box(&buf);
    }
    let noalloc_elapsed = start2.elapsed();
    let noalloc_tput = alloc_mb / noalloc_elapsed.as_secs_f64();

    println!(
        "  Vec::clone (alloc every time): {:>10.1} MiB/s", alloc_tput
    );
    println!(
        "  copy_from_slice (zero alloc):  {:>10.1} MiB/s", noalloc_tput
    );
    println!(
        "  Alloc overhead: {:.1}x slower",
        noalloc_tput / alloc_tput
    );
}

fn format_size(n: usize) -> String {
    if n >= 1_048_576 { format!("{} MB", n / 1_048_576) }
    else if n >= 1024 { format!("{} KB", n / 1024) }
    else { format!("{} B", n) }
}
