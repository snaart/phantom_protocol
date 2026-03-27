//! Complete Protocol Comparison Benchmarks (recompile)
//!
//! Real comparison of:
//! - Phantom PQC Transport encryption
//! - Raw TCP echo (no encryption)
//! - Classical vs Post-Quantum cryptography

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

// Phantom imports
use phantom_core::crypto::hybrid_kem::HybridSecretKey;
use phantom_core::crypto::hybrid_sign::HybridSigningKey;
use phantom_core::transport::handshake::{HandshakeClient, HandshakeResponse, HandshakeServer};

// ============================================================================
// PHANTOM PQC BENCHMARKS
// ============================================================================

fn phantom_handshake_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake_comparison");
    group.measurement_time(Duration::from_secs(15));

    // Phantom PQC Handshake (full, with server-key pinning enabled — matches prod path)
    group.bench_function("phantom_pqc_full", |b| {
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
                _ => panic!("Expected retry, got {:?}", result),
            };

            let mut client_hello_retry = client_hello.clone();
            client_hello_retry.cookie = Some(cookie);

            let result = server.process_client_hello(&client_hello_retry, 0, client_ip);
            let (server_hello, _) = match result {
                HandshakeResponse::Success(h, s) => (h, s),
                _ => panic!("Expected success, got {:?}", result),
            };
            let _ = client
                .process_server_hello(&client_hello_retry, &server_hello, Some(&server_pk))
                .unwrap();

            black_box(())
        })
    });

    group.finish();
}

fn phantom_throughput_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_comparison");
    group.measurement_time(Duration::from_secs(10));

    // Setup Phantom session once
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

    // Different payload sizes
    for size in [1024, 4096, 16384, 65536].iter() {
        let data = vec![0xAB; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        let header = phantom_core::transport::types::PacketHeader::new(
            *server_session.id(),
            1,
            1,
            phantom_core::transport::types::PacketFlags::empty(),
        );

        group.bench_with_input(BenchmarkId::new("phantom_encrypt", size), size, |b, _| {
            b.iter(|| {
                let encrypted = server_session.encrypt_packet(&header, &data).unwrap();
                black_box(encrypted)
            })
        });

        let encrypted = server_session.encrypt_packet(&header, &data).unwrap();
        group.bench_with_input(BenchmarkId::new("phantom_decrypt", size), size, |b, _| {
            b.iter(|| {
                let decrypted = client_session.decrypt_packet(&header, &encrypted).unwrap();
                black_box(decrypted)
            })
        });

        group.bench_with_input(BenchmarkId::new("phantom_roundtrip", size), size, |b, _| {
            b.iter(|| {
                let encrypted = server_session.encrypt_packet(&header, &data).unwrap();
                let decrypted = client_session.decrypt_packet(&header, &encrypted).unwrap();
                black_box(decrypted)
            })
        });
    }

    group.finish();
}

// ============================================================================
// CRYPTO OPERATIONS COMPARISON: Classical vs Post-Quantum
// ============================================================================

fn crypto_comparison_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_pq_vs_classical");
    group.measurement_time(Duration::from_secs(10));

    // === Key Generation ===

    // Classical: Ed25519 only
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use rand::rngs::OsRng;

    group.bench_function("keygen_ed25519", |b| {
        b.iter(|| {
            let sk = SigningKey::generate(&mut OsRng);
            black_box(sk)
        })
    });

    // Post-Quantum: ML-DSA-65 only (Phase 5.1 — was Dilithium3 / pqcrypto)
    use ml_dsa::{Generate, MlDsa65, SigningKey as MlDsaSigningKey};

    group.bench_function("keygen_ml_dsa_65", |b| {
        b.iter(|| {
            let sk = MlDsaSigningKey::<MlDsa65>::generate();
            black_box(sk)
        })
    });

    // Hybrid: Ed25519 + ML-DSA-65
    group.bench_function("keygen_hybrid_sign", |b| {
        b.iter(|| {
            let (sk, pk) = HybridSigningKey::generate();
            black_box((sk, pk))
        })
    });

    // Classical: X25519 only
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    group.bench_function("keygen_x25519", |b| {
        b.iter(|| {
            let sk = StaticSecret::random_from_rng(OsRng);
            let pk = X25519PublicKey::from(&sk);
            black_box((sk, pk))
        })
    });

    // Post-Quantum: ML-KEM-768 only (Phase 5.1 — was Kyber768 / pqcrypto)
    use ml_kem::{KemCore, MlKem768};

    group.bench_function("keygen_ml_kem_768", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let (dk, ek) = MlKem768::generate(&mut rng);
            black_box((dk, ek))
        })
    });

    // Hybrid: X25519 + Kyber768
    group.bench_function("keygen_hybrid_kem", |b| {
        b.iter(|| {
            let (sk, pk) = HybridSecretKey::generate();
            black_box((sk, pk))
        })
    });

    // === Signing ===
    let message = b"Benchmark message for signing operations - this is a typical message length";

    let ed_sk = SigningKey::generate(&mut OsRng);
    group.bench_function("sign_ed25519", |b| {
        b.iter(|| {
            let sig = ed_sk.sign(message);
            black_box(sig)
        })
    });

    let ml_dsa_sk_bench = MlDsaSigningKey::<MlDsa65>::generate();
    group.bench_function("sign_ml_dsa_65", |b| {
        b.iter(|| {
            use ml_dsa::Signer;
            let sig: ml_dsa::Signature<MlDsa65> = ml_dsa_sk_bench.sign(message);
            black_box(sig)
        })
    });

    let (hybrid_sk, _) = HybridSigningKey::generate();
    group.bench_function("sign_hybrid", |b| {
        b.iter(|| {
            let sig = hybrid_sk.sign(message);
            black_box(sig)
        })
    });

    // === Verification ===
    let ed_vk = ed_sk.verifying_key();
    let ed_sig = ed_sk.sign(message);
    group.bench_function("verify_ed25519", |b| {
        b.iter(|| {
            let result = ed_vk.verify(message, &ed_sig);
            black_box(result)
        })
    });

    let ml_dsa_sk_verify = MlDsaSigningKey::<MlDsa65>::generate();
    let ml_dsa_vk_verify = {
        use ml_dsa::Keypair;
        ml_dsa_sk_verify.verifying_key()
    };
    let ml_dsa_sig = {
        use ml_dsa::Signer;
        ml_dsa_sk_verify.sign(message)
    };
    group.bench_function("verify_ml_dsa_65", |b| {
        b.iter(|| {
            use ml_dsa::Verifier;
            let result = ml_dsa_vk_verify.verify(message, &ml_dsa_sig);
            black_box(result)
        })
    });

    let (hybrid_sk2, hybrid_vk) = HybridSigningKey::generate();
    let hybrid_sig = hybrid_sk2.sign(message);
    group.bench_function("verify_hybrid", |b| {
        b.iter(|| {
            let result = hybrid_vk.verify(message, &hybrid_sig);
            black_box(result)
        })
    });

    // === KEM Operations ===
    let (_, kem_pk) = HybridSecretKey::generate();
    group.bench_function("kem_encapsulate_hybrid", |b| {
        b.iter(|| {
            let result = kem_pk.encapsulate();
            black_box(result)
        })
    });

    let (kem_sk, kem_pk2) = HybridSecretKey::generate();
    let (_, ciphertext) = kem_pk2.encapsulate().unwrap();
    group.bench_function("kem_decapsulate_hybrid", |b| {
        b.iter(|| {
            let shared = kem_sk.decapsulate(&ciphertext);
            black_box(shared)
        })
    });

    group.finish();
}

// ============================================================================
// ENCRYPTION COMPARISON: ChaCha20-Poly1305 at different sizes
// ============================================================================

fn encryption_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption_sizes");
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

    for size in [64, 256, 1024, 4096, 16384, 65536, 262144, 1048576].iter() {
        let data = vec![0xAB; *size];
        group.throughput(Throughput::Bytes(*size as u64 * 2)); // encrypt + decrypt

        let header = phantom_core::transport::types::PacketHeader::new(
            *server_session.id(),
            1,
            1,
            phantom_core::transport::types::PacketFlags::empty(),
        );

        group.bench_with_input(BenchmarkId::new("chacha20poly1305", size), size, |b, _| {
            b.iter(|| {
                let encrypted = server_session.encrypt_packet(&header, &data).unwrap();
                let decrypted = client_session.decrypt_packet(&header, &encrypted).unwrap();
                black_box(decrypted)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    phantom_handshake_bench,
    phantom_throughput_bench,
    crypto_comparison_bench,
    encryption_bench,
);
criterion_main!(benches);
