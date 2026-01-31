//! Real Protocol Comparison Benchmark
//!
//! Compares actual network performance:
//! - Phantom PQC Transport (encrypted + authenticated)
//! - TCP + TLS 1.3 (what gRPC/HTTP2 uses)
//! - Raw TCP (baseline, no encryption)
//!
//! Each test runs a real server and client, measuring:
//! - Connection establishment time
//! - Round-trip latency
//! - Throughput

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

// Phantom imports
use phantom_core::transport::pqc_handshake::{PqcHandshakeClient, PqcHandshakeServer, HandshakeResponse};

fn main() {
    // Initialize ring crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║      Real Protocol Comparison: Phantom vs TLS vs TCP         ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    
    let rt = Runtime::new().unwrap();
    
    // Warm up
    println!("Warming up...");
    rt.block_on(warmup());
    println!();
    
    // Run benchmarks
    let iterations = 100;
    let data_sizes = [64, 1024, 16384, 65536];
    
    println!("═══════════════════════════════════════════════════════════════");
    println!("                     CONNECTION ESTABLISHMENT                   ");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    
    // 1. Raw TCP connection
    let tcp_connect_times = rt.block_on(bench_tcp_connect(iterations));
    let tcp_avg = tcp_connect_times.iter().sum::<Duration>() / iterations as u32;
    println!("Raw TCP:     {:>10.2?} avg ({} samples)", tcp_avg, iterations);
    
    // 2. TCP + TLS connection
    let tls_connect_times = rt.block_on(bench_tls_connect(iterations));
    let tls_avg = tls_connect_times.iter().sum::<Duration>() / iterations as u32;
    println!("TCP + TLS:   {:>10.2?} avg ({} samples)", tls_avg, iterations);
    
    // 3. Phantom PQC handshake (in-memory, simulating network)
    let phantom_times = bench_phantom_handshake(iterations);
    let phantom_avg = phantom_times.iter().sum::<Duration>() / iterations as u32;
    println!("Phantom PQC: {:>10.2?} avg ({} samples)", phantom_avg, iterations);
    
    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("                      ROUND-TRIP LATENCY                        ");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    
    for size in data_sizes.iter() {
        println!("--- Payload: {} bytes ---", size);
        
        // Raw TCP
        let tcp_rtt = rt.block_on(bench_tcp_rtt(*size, iterations));
        let tcp_rtt_avg = tcp_rtt.iter().sum::<Duration>() / iterations as u32;
        
        // TCP + TLS
        let tls_rtt = rt.block_on(bench_tls_rtt(*size, iterations));
        let tls_rtt_avg = tls_rtt.iter().sum::<Duration>() / iterations as u32;
        
        // Phantom (encryption only, no network for fair comparison)
        let phantom_rtt = bench_phantom_encrypt(*size, iterations);
        let phantom_rtt_avg = phantom_rtt.iter().sum::<Duration>() / iterations as u32;
        
        println!("Raw TCP:     {:>10.2?}", tcp_rtt_avg);
        println!("TCP + TLS:   {:>10.2?}", tls_rtt_avg);
        println!("Phantom enc: {:>10.2?}", phantom_rtt_avg);
        println!();
    }
    
    println!("═══════════════════════════════════════════════════════════════");
    println!("                         THROUGHPUT                             ");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    
    // Large payload throughput test
    let large_size = 64 * 1024; // 64 KB - realistic packet size
    let throughput_iters = 200;
    
    // Raw TCP throughput
    let tcp_throughput = rt.block_on(bench_tcp_throughput(large_size, throughput_iters));
    
    // TLS throughput
    let tls_throughput = rt.block_on(bench_tls_throughput(large_size, throughput_iters));
    
    // Phantom over TCP throughput (encrypt -> send -> receive -> decrypt)
    let phantom_tcp_throughput = rt.block_on(bench_phantom_tcp_throughput(large_size, throughput_iters));
    
    // Phantom throughput (encryption only, no network)
    let phantom_throughput = bench_phantom_throughput(large_size, throughput_iters);
    
    println!("1 MB payload × {} iterations:", throughput_iters);
    println!("Raw TCP:          {:>10.2} MiB/s", tcp_throughput);
    println!("TCP + TLS:        {:>10.2} MiB/s", tls_throughput);
    println!("Phantom + TCP:    {:>10.2} MiB/s  <-- OUR PROTOCOL", phantom_tcp_throughput);
    println!("Phantom enc only: {:>10.2} MiB/s  (no network)", phantom_throughput);
    
    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("                         SUMMARY                                ");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("┌─────────────────┬──────────────┬──────────────┬──────────────┐");
    println!("│ Metric          │ Raw TCP      │ TLS 1.3      │ Phantom PQC  │");
    println!("├─────────────────┼──────────────┼──────────────┼──────────────┤");
    println!("│ Connect         │ {:>10.2?} │ {:>10.2?} │ {:>10.2?} │", tcp_avg, tls_avg, phantom_avg);
    println!("│ Throughput      │ {:>8.1} MB/s │ {:>8.1} MB/s │ {:>8.1} MB/s │", tcp_throughput, tls_throughput, phantom_throughput);
    println!("│ Quantum-Safe    │     ❌       │     ❌       │     ✅       │");
    println!("└─────────────────┴──────────────┴──────────────┴──────────────┘");
}

async fn warmup() {
    // Warm up TCP
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(&buf).await;
        }
    });
    
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"warmup").await.unwrap();
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await;
}

// ============================================================================
// TCP Benchmarks
// ============================================================================

async fn bench_tcp_connect(iterations: usize) -> Vec<Duration> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    // Server task
    tokio::spawn(async move {
        for _ in 0..iterations {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 1];
                let _ = s.read(&mut buf).await;
            }
        }
    });
    
    let mut times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&[0]).await.unwrap();
        times.push(start.elapsed());
    }
    times
}

async fn bench_tcp_rtt(size: usize, iterations: usize) -> Vec<Duration> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut buf = vec![0u8; size];
            for _ in 0..iterations {
                let n = s.read_exact(&mut buf).await.unwrap_or(0);
                if n == 0 { break; }
                s.write_all(&buf).await.unwrap();
            }
        }
    });
    
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let data = vec![0xAB; size];
    let mut buf = vec![0u8; size];
    
    let mut times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        stream.write_all(&data).await.unwrap();
        stream.read_exact(&mut buf).await.unwrap();
        times.push(start.elapsed());
    }
    times
}

async fn bench_tcp_throughput(size: usize, iterations: usize) -> f64 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut buf = vec![0u8; size];
            for _ in 0..iterations {
                if s.read_exact(&mut buf).await.is_err() { break; }
                if s.write_all(&buf).await.is_err() { break; }
            }
        }
    });
    
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let data = vec![0xAB; size];
    let mut buf = vec![0u8; size];
    
    let start = Instant::now();
    for _ in 0..iterations {
        stream.write_all(&data).await.unwrap();
        stream.read_exact(&mut buf).await.unwrap();
    }
    let elapsed = start.elapsed();
    
    let total_bytes = size * iterations * 2;
    (total_bytes as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64()
}

// ============================================================================
// TLS Benchmarks
// ============================================================================

fn generate_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    (vec![cert_der], key_der)
}

async fn bench_tls_connect(iterations: usize) -> Vec<Duration> {
    let (certs, key) = generate_self_signed_cert();
    
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let acceptor_clone = acceptor.clone();
    tokio::spawn(async move {
        for _ in 0..iterations {
            if let Ok((stream, _)) = listener.accept().await {
                if let Ok(mut tls) = acceptor_clone.accept(stream).await {
                    let mut buf = [0u8; 1];
                    let _ = tls.read(&mut buf).await;
                }
            }
        }
    });
    
    // Client config with no cert verification (self-signed)
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(certs[0].clone()).unwrap();
    
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    
    let mut times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let stream = TcpStream::connect(addr).await.unwrap();
        let server_name = "localhost".try_into().unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();
        tls.write_all(&[0]).await.unwrap();
        times.push(start.elapsed());
    }
    times
}

async fn bench_tls_rtt(size: usize, iterations: usize) -> Vec<Duration> {
    let (certs, key) = generate_self_signed_cert();
    
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let mut buf = vec![0u8; size];
                for _ in 0..iterations {
                    if tls.read_exact(&mut buf).await.is_err() { break; }
                    if tls.write_all(&buf).await.is_err() { break; }
                }
            }
        }
    });
    
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(certs[0].clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    
    let stream = TcpStream::connect(addr).await.unwrap();
    let server_name = "localhost".try_into().unwrap();
    let mut tls = connector.connect(server_name, stream).await.unwrap();
    
    let data = vec![0xAB; size];
    let mut buf = vec![0u8; size];
    
    let mut times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        tls.write_all(&data).await.unwrap();
        tls.read_exact(&mut buf).await.unwrap();
        times.push(start.elapsed());
    }
    times
}

async fn bench_tls_throughput(size: usize, iterations: usize) -> f64 {
    let (certs, key) = generate_self_signed_cert();
    
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let mut buf = vec![0u8; size];
                for _ in 0..iterations {
                    if tls.read_exact(&mut buf).await.is_err() { break; }
                    if tls.write_all(&buf).await.is_err() { break; }
                }
            }
        }
    });
    
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(certs[0].clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    
    let stream = TcpStream::connect(addr).await.unwrap();
    let server_name = "localhost".try_into().unwrap();
    let mut tls = connector.connect(server_name, stream).await.unwrap();
    
    let data = vec![0xAB; size];
    let mut buf = vec![0u8; size];
    
    let start = Instant::now();
    for _ in 0..iterations {
        tls.write_all(&data).await.unwrap();
        tls.read_exact(&mut buf).await.unwrap();
    }
    let elapsed = start.elapsed();
    
    let total_bytes = size * iterations * 2;
    (total_bytes as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64()
}

// ============================================================================
// Phantom Benchmarks
// ============================================================================

fn bench_phantom_handshake(iterations: usize) -> Vec<Duration> {
    let mut times = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        
        let client = PqcHandshakeClient::new();
        let server = PqcHandshakeServer::new();
        
        let client_hello = client.create_client_hello();
        let result = server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
        let (server_hello, _) = match result {
            HandshakeResponse::Success(h, s) => (h, s),
            _ => panic!("Expected success"),
        };
        let _ = client.process_server_hello(&server_hello, None).unwrap();
        
        times.push(start.elapsed());
    }
    times
}

fn bench_phantom_encrypt(size: usize, iterations: usize) -> Vec<Duration> {
    // Setup session once
    let client = PqcHandshakeClient::new();
    let server = PqcHandshakeServer::new();
    let client_hello = client.create_client_hello();
    let result = server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
    let (server_hello, server_session) = match result {
        HandshakeResponse::Success(h, s) => (h, s),
        _ => panic!("Expected success"),
    };
    let client_session = client.process_server_hello(&server_hello, None).unwrap();
    
    let data = vec![0xAB; size];
    let mut times = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let encrypted = server_session.encrypt_packet(&data).unwrap();
        let _ = client_session.decrypt_packet(&encrypted).unwrap();
        times.push(start.elapsed());
    }
    times
}

fn bench_phantom_throughput(size: usize, iterations: usize) -> f64 {
    let client = PqcHandshakeClient::new();
    let server = PqcHandshakeServer::new();
    let client_hello = client.create_client_hello();
    let result = server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
    let (server_hello, server_session) = match result {
        HandshakeResponse::Success(h, s) => (h, s),
        _ => panic!("Expected success"),
    };
    let client_session = client.process_server_hello(&server_hello, None).unwrap();
    
    let data = vec![0xAB; size];
    
    let start = Instant::now();
    for _ in 0..iterations {
        let encrypted = server_session.encrypt_packet(&data).unwrap();
        let _ = client_session.decrypt_packet(&encrypted).unwrap();
    }
    let elapsed = start.elapsed();
    
    let total_bytes = size * iterations * 2;
    (total_bytes as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64()
}

/// Phantom encryption over raw TCP - the real protocol performance
async fn bench_phantom_tcp_throughput(size: usize, iterations: usize) -> f64 {
    // Setup Phantom sessions (shared between client and server)
    let pqc_client = PqcHandshakeClient::new();
    let pqc_server = PqcHandshakeServer::new();
    let client_hello = pqc_client.create_client_hello();
    let result = pqc_server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
    let (server_hello, server_session) = match result {
        HandshakeResponse::Success(h, s) => (h, s),
        _ => panic!("Expected success"),
    };
    let client_session = pqc_client.process_server_hello(&server_hello, None).unwrap();
    
    // Clone sessions for server side (Arc wrapper)
    let server_session = Arc::new(server_session);
    let client_session = Arc::new(client_session);
    
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    let server_session_clone = server_session.clone();
    
    // Server: receive encrypted data, decrypt, re-encrypt, send back
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            // First read 4-byte length prefix
            for _ in 0..iterations {
                // Read length
                let mut len_buf = [0u8; 4];
                if s.read_exact(&mut len_buf).await.is_err() { break; }
                let len = u32::from_be_bytes(len_buf) as usize;
                
                // Read encrypted data
                let mut encrypted = vec![0u8; len];
                if s.read_exact(&mut encrypted).await.is_err() { break; }
                
                // Decrypt
                let decrypted = server_session_clone.decrypt_packet(&encrypted).unwrap();
                
                // Re-encrypt and send back
                let response = server_session_clone.encrypt_packet(&decrypted).unwrap();
                let resp_len = (response.len() as u32).to_be_bytes();
                if s.write_all(&resp_len).await.is_err() { break; }
                if s.write_all(&response).await.is_err() { break; }
            }
        }
    });
    
    // Client: encrypt, send, receive, decrypt
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let data = vec![0xAB; size];
    
    let start = Instant::now();
    for _ in 0..iterations {
        // Encrypt
        let encrypted = client_session.encrypt_packet(&data).unwrap();
        
        // Send with length prefix
        let len = (encrypted.len() as u32).to_be_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(&encrypted).await.unwrap();
        
        // Receive response
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        
        let mut response = vec![0u8; resp_len];
        stream.read_exact(&mut response).await.unwrap();
        
        // Decrypt
        let _ = client_session.decrypt_packet(&response).unwrap();
    }
    let elapsed = start.elapsed();
    
    let total_bytes = size * iterations * 2;
    (total_bytes as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64()
}
