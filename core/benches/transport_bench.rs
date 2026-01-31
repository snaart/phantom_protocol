//! Phantom Transport Benchmarks
//!
//! Compares performance of:
//! - Phantom PQC handshake
//! - Phantom data transfer
//! - gRPC (tonic) baseline
//! - HTTP (hyper) baseline

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::time::Duration;

// Import Phantom types
use phantom_core::transport::pqc_handshake::{PqcHandshakeClient, PqcHandshakeServer, HandshakeResponse};
use phantom_core::crypto::hybrid_kem::HybridSecretKey;
use phantom_core::crypto::hybrid_sign::HybridSigningKey;

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
    
    // Phantom PQC handshake
    group.bench_function("phantom_pqc_handshake", |b| {
        b.iter(|| {
            let client = PqcHandshakeClient::new();
            let server = PqcHandshakeServer::new();
            
            let client_hello = client.create_client_hello();
            let result = server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
            let (server_hello, _server_session) = match result {
                HandshakeResponse::Success(h, s) => (h, s),
                _ => panic!("Expected success"),
            };
            let _client_session = client.process_server_hello(&server_hello, None).unwrap();
            
            black_box(())
        })
    });
    
    // Phantom handshake with key pinning
    group.bench_function("phantom_pqc_handshake_pinned", |b| {
        let server = PqcHandshakeServer::new();
        let server_pk = server.verifying_key().clone();
        
        b.iter(|| {
            let client = PqcHandshakeClient::new();
            
            let client_hello = client.create_client_hello();
            let result = server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
            let (server_hello, _server_session) = match result {
                HandshakeResponse::Success(h, s) => (h, s),
                _ => panic!("Expected success"),
            };
            let _client_session = client.process_server_hello(&server_hello, Some(&server_pk)).unwrap();
            
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
    let client = PqcHandshakeClient::new();
    let server = PqcHandshakeServer::new();
    let client_hello = client.create_client_hello();
    let result = server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
    let (server_hello, server_session) = match result {
        HandshakeResponse::Success(h, s) => (h, s),
        _ => panic!("Expected success"),
    };
    let client_session = client.process_server_hello(&server_hello, None).unwrap();
    
    // Benchmark different payload sizes
    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let data = vec![0xAB; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, _| {
            b.iter(|| {
                let encrypted = server_session.encrypt_packet(&data);
                black_box(encrypted)
            })
        });
        
        let encrypted = server_session.encrypt_packet(&data).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", size), size, |b, _| {
            b.iter(|| {
                let decrypted = client_session.decrypt_packet(&encrypted);
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
    let client = PqcHandshakeClient::new();
    let server = PqcHandshakeServer::new();
    let client_hello = client.create_client_hello();
    let result = server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
    let (server_hello, server_session) = match result {
        HandshakeResponse::Success(h, s) => (h, s),
        _ => panic!("Expected success"),
    };
    let client_session = client.process_server_hello(&server_hello, None).unwrap();
    
    // 1MB payload
    let data = vec![0xAB; 1024 * 1024];
    group.throughput(Throughput::Bytes(data.len() as u64 * 2)); // encrypt + decrypt
    
    group.bench_function("1MB_roundtrip", |b| {
        b.iter(|| {
            let encrypted = server_session.encrypt_packet(&data).unwrap();
            let decrypted = client_session.decrypt_packet(&encrypted).unwrap();
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
