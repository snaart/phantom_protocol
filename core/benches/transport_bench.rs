//! Phantom Protocol Benchmarks
//!
//! Compares performance of:
//! - Phantom Protocol PQC handshake
//! - Phantom Protocol data transfer
//! - gRPC (tonic) baseline
//! - HTTP (hyper) baseline

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

// Import Phantom Protocol types
use phantom_protocol::crypto::hybrid_kem::HybridSecretKey;
use phantom_protocol::crypto::hybrid_sign::HybridSigningKey;
use phantom_protocol::transport::handshake::{HandshakeClient, HandshakeResponse, HandshakeServer};
use phantom_protocol::transport::types::{PacketFlags, PacketHeader};

/// Benchmark PQC key generation
fn bench_pqc_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_keygen");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("hybrid_kem_keygen", |b| {
        b.iter(|| {
            let (sk, pk) = HybridSecretKey::generate();
            black_box((sk, pk))
        })
    });

    group.bench_function("hybrid_sign_keygen", |b| {
        b.iter(|| {
            let (sk, pk) = HybridSigningKey::generate();
            black_box((sk, pk))
        })
    });

    group.finish();
}

/// Benchmark PQC operations
fn bench_pqc_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_operations");
    group.measurement_time(Duration::from_secs(10));

    // Setup keys
    let (kem_sk, kem_pk) = HybridSecretKey::generate();
    let (sign_sk, sign_vk) = HybridSigningKey::generate();
    let message = b"Benchmark message for signing operations";

    // KEM encapsulation
    group.bench_function("kem_encapsulate", |b| {
        b.iter(|| {
            let result = kem_pk.encapsulate();
            black_box(result)
        })
    });

    // KEM decapsulation
    let (_, ciphertext) = kem_pk.encapsulate().unwrap();
    group.bench_function("kem_decapsulate", |b| {
        b.iter(|| {
            let shared = kem_sk.decapsulate(&ciphertext);
            black_box(shared)
        })
    });

    // Sign
    group.bench_function("hybrid_sign", |b| {
        b.iter(|| {
            let sig = sign_sk.sign(message);
            black_box(sig)
        })
    });

    // Verify
    let signature = sign_sk.sign(message);
    group.bench_function("hybrid_verify", |b| {
        b.iter(|| {
            let result = sign_vk.verify(message, &signature);
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark handshake
fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.measurement_time(Duration::from_secs(15));

    // Phantom Protocol PQC handshake (unpinned — measures handshake without identity check).
    // NOTE: production code path requires pinning (see PhantomSession); this
    // variant exists purely to isolate handshake performance.
    group.bench_function("phantom_pqc_handshake", |b| {
        let client_ip = "127.0.0.1".parse().unwrap();
        b.iter(|| {
            let client = HandshakeClient::new().expect("HandshakeClient::new");
            let server = HandshakeServer::new().unwrap();
            let server_pk = server.verifying_key().clone();

            let client_hello = client.create_client_hello();
            let result = server.process_client_hello(&client_hello, 0, client_ip);

            // Handle mandatory cookie retry
            let cookie = match result {
                HandshakeResponse::Retry(r) => r.cookie.unwrap(),
                _ => panic!("Expected retry"),
            };

            let mut client_hello_retry = client_hello.clone();
            client_hello_retry.cookie = Some(cookie);

            let result = server.process_client_hello(&client_hello_retry, 0, client_ip);
            let (server_hello, _server_session) = match result {
                HandshakeResponse::Success(h, s, _) => (h, s),
                _ => panic!("Expected success"),
            };
            let _client_session = client
                .process_server_hello(&client_hello_retry, &server_hello, Some(&server_pk))
                .unwrap();

            black_box(())
        })
    });

    // Phantom Protocol handshake with key pinning
    group.bench_function("phantom_pqc_handshake_pinned", |b| {
        let server = HandshakeServer::new().unwrap();
        let server_pk = server.verifying_key().clone();
        let client_ip = "127.0.0.1".parse().unwrap();

        b.iter(|| {
            let client = HandshakeClient::new().expect("HandshakeClient::new");

            let client_hello = client.create_client_hello();
            let result = server.process_client_hello(&client_hello, 0, client_ip);

            // Handle mandatory cookie retry
            let cookie = match result {
                HandshakeResponse::Retry(r) => r.cookie.unwrap(),
                _ => panic!("Expected retry"),
            };

            let mut client_hello_retry = client_hello.clone();
            client_hello_retry.cookie = Some(cookie);

            let result = server.process_client_hello(&client_hello_retry, 0, client_ip);
            let (server_hello, _server_session) = match result {
                HandshakeResponse::Success(h, s, _) => (h, s),
                _ => panic!("Expected success"),
            };
            let _client_session = client
                .process_server_hello(&client_hello_retry, &server_hello, Some(&server_pk))
                .unwrap();

            black_box(())
        })
    });

    group.finish();
}

/// Benchmark encryption/decryption
fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");
    group.measurement_time(Duration::from_secs(10));

    // Setup session
    let client = HandshakeClient::new().expect("HandshakeClient::new");
    let server = HandshakeServer::new().unwrap();
    let server_pk = server.verifying_key().clone();
    let client_ip = "127.0.0.1".parse().unwrap();
    let client_hello = client.create_client_hello();
    let result = server.process_client_hello(&client_hello, 0, client_ip);

    // Handle mandatory cookie retry
    let cookie = match result {
        HandshakeResponse::Retry(r) => r.cookie.unwrap(),
        _ => panic!("Expected retry"),
    };

    let mut client_hello_retry = client_hello.clone();
    client_hello_retry.cookie = Some(cookie);

    let result = server.process_client_hello(&client_hello_retry, 0, client_ip);
    let (server_hello, server_session) = match result {
        HandshakeResponse::Success(h, s, _) => (h, s),
        _ => panic!("Expected success"),
    };
    let (client_session, _) = client
        .process_server_hello(&client_hello_retry, &server_hello, Some(&server_pk))
        .unwrap();

    // Benchmark different payload sizes.
    //
    // V2 wire format (`encrypt_packet` / `decrypt_packet`) derives the
    // AEAD nonce from the authenticated header fields rather than an internal
    // monotonic counter, so a sender/receiver pair cannot desync. To stay
    // clear of the per-stream sliding-window replay guard, each iteration
    // uses a fresh `header.sequence` from a monotonic counter that is
    // hoisted outside the payload-size loop (so it never resets and never
    // collides with a previously-accepted sequence on the same stream).
    let session_id = *server_session.id();
    let flags = PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE);
    let encrypt_seq = AtomicU32::new(1);
    let decrypt_seq = AtomicU32::new(1);

    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let data = vec![0xAB; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        // Encrypt-only — encrypt has no replay-window dependency, but using
        // V2 keeps both halves consistent.
        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, _| {
            b.iter_batched(
                || {
                    let seq = encrypt_seq.fetch_add(1, Ordering::Relaxed);
                    PacketHeader::new(session_id, 1, seq as u64, flags)
                },
                |header| {
                    let encrypted = server_session.encrypt_packet(&header, &data);
                    black_box(encrypted)
                },
                BatchSize::SmallInput,
            )
        });

        // Dedicated stream id (2) for the decrypt half so its sliding-window
        // state is independent from the encrypt side's stream 1.
        group.bench_with_input(BenchmarkId::new("decrypt", size), size, |b, _| {
            b.iter_batched(
                || {
                    let seq = decrypt_seq.fetch_add(1, Ordering::Relaxed);
                    let header = PacketHeader::new(session_id, 2, seq as u64, flags);
                    let encrypted = server_session
                        .encrypt_packet(&header, &data)
                        .expect("encrypt setup");
                    (header, encrypted)
                },
                |(header, encrypted)| {
                    let decrypted = client_session.decrypt_packet(&header, &encrypted);
                    black_box(decrypted)
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

/// Benchmark session throughput
fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    // Setup session
    let client = HandshakeClient::new().expect("HandshakeClient::new");
    let server = HandshakeServer::new().unwrap();
    let server_pk = server.verifying_key().clone();
    let client_ip = "127.0.0.1".parse().unwrap();
    let client_hello = client.create_client_hello();
    let result = server.process_client_hello(&client_hello, 0, client_ip);

    // Handle mandatory cookie retry
    let cookie = match result {
        HandshakeResponse::Retry(r) => r.cookie.unwrap(),
        _ => panic!("Expected retry"),
    };

    let mut client_hello_retry = client_hello.clone();
    client_hello_retry.cookie = Some(cookie);

    let result = server.process_client_hello(&client_hello_retry, 0, client_ip);
    let (server_hello, server_session) = match result {
        HandshakeResponse::Success(h, s, _) => (h, s),
        _ => panic!("Expected success"),
    };
    let (client_session, _) = client
        .process_server_hello(&client_hello_retry, &server_hello, Some(&server_pk))
        .unwrap();

    // 1MB payload
    let data = vec![0xAB; 1024 * 1024];
    group.throughput(Throughput::Bytes(data.len() as u64 * 2)); // encrypt + decrypt

    // Switched to V2 (`encrypt_packet` / `decrypt_packet`) so the AEAD
    // nonce is header-derived and a sender/receiver pair cannot desync. Each
    // iteration bumps `header.sequence` to dodge the per-stream replay window.
    let session_id = *server_session.id();
    let flags = PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE);
    let seq_counter = AtomicU32::new(1);

    group.bench_function("1MB_roundtrip", |b| {
        b.iter_batched(
            || {
                let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
                PacketHeader::new(session_id, 1, seq as u64, flags)
            },
            |header| {
                let encrypted = server_session.encrypt_packet(&header, &data).unwrap();
                let decrypted = client_session.decrypt_packet(&header, &encrypted).unwrap();
                black_box(decrypted)
            },
            BatchSize::PerIteration,
        )
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_pqc_keygen,
    bench_pqc_operations,
    bench_handshake,
    bench_encryption,
    bench_throughput,
);
criterion_main!(benches);
