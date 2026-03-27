//! Phantom Transport Benchmarks
//!
//! Compares performance of:
//! - Phantom PQC handshake
//! - Phantom data transfer
//! - gRPC (tonic) baseline
//! - HTTP (hyper) baseline

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

// Import Phantom types
use phantom_core::crypto::hybrid_kem::HybridSecretKey;
use phantom_core::crypto::hybrid_sign::HybridSigningKey;
use phantom_core::transport::handshake::{HandshakeClient, HandshakeResponse, HandshakeServer};

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

    // Phantom PQC handshake (unpinned — measures handshake without identity check).
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
                HandshakeResponse::Success(h, s) => (h, s),
                _ => panic!("Expected success"),
            };
            let _client_session = client
                .process_server_hello(&client_hello_retry, &server_hello, Some(&server_pk))
                .unwrap();

            black_box(())
        })
    });

    // Phantom handshake with key pinning
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
                HandshakeResponse::Success(h, s) => (h, s),
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
        HandshakeResponse::Success(h, s) => (h, s),
        _ => panic!("Expected success"),
    };
    let client_session = client
        .process_server_hello(&client_hello_retry, &server_hello, Some(&server_pk))
        .unwrap();

    // Benchmark different payload sizes
    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let data = vec![0xAB; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        let header = phantom_core::transport::types::PacketHeader::new(
            *server_session.id(),
            1,
            1,
            phantom_core::transport::types::PacketFlags::empty(),
        );

        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, _| {
            b.iter(|| {
                let encrypted = server_session.encrypt_packet(&header, &data);
                black_box(encrypted)
            })
        });

        let encrypted = server_session.encrypt_packet(&header, &data).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", size), size, |b, _| {
            b.iter(|| {
                let decrypted = client_session.decrypt_packet(&header, &encrypted);
                black_box(decrypted)
            })
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
        HandshakeResponse::Success(h, s) => (h, s),
        _ => panic!("Expected success"),
    };
    let client_session = client
        .process_server_hello(&client_hello_retry, &server_hello, Some(&server_pk))
        .unwrap();

    // 1MB payload
    let data = vec![0xAB; 1024 * 1024];
    group.throughput(Throughput::Bytes(data.len() as u64 * 2)); // encrypt + decrypt

    let header = phantom_core::transport::types::PacketHeader::new(
        *server_session.id(),
        1,
        1,
        phantom_core::transport::types::PacketFlags::empty(),
    );

    group.bench_function("1MB_roundtrip", |b| {
        b.iter(|| {
            let encrypted = server_session.encrypt_packet(&header, &data).unwrap();
            let decrypted = client_session.decrypt_packet(&header, &encrypted).unwrap();
            black_box(decrypted)
        })
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
