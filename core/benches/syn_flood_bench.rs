use borsh::BorshDeserialize;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use phantom_core::transport::handshake::{ClientHello, HandshakeClient, HandshakeServer};
use phantom_core::transport::reputation::ReputationTracker;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn bench_syn_flood(c: &mut Criterion) {
    let mut group = c.benchmark_group("SYN Flood (5KB UDP Handshake)");

    // Setup server and reputation tracker
    let server = Arc::new(HandshakeServer::new().unwrap());
    let reputation = Arc::new(ReputationTracker::new());

    // Create a legitimate-looking ClientHello payload
    let client = HandshakeClient::new().expect("HandshakeClient::new");
    let original_hello = client.create_client_hello();
    let payload = borsh::to_vec(&original_hello).unwrap();

    // Bench: Parsing + Reputation + Cookie generation
    group.throughput(Throughput::Bytes(payload.len() as u64));

    group.bench_function("Process ClientHello (Parse + Cookie + Rep)", |b| {
        b.iter(|| {
            // Generate a random-ish IP
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, (rand::random::<u8>() % 254) + 1));

            // Simulating UdpHandshakeListener logic:
            if payload.len() < 1200 {
                // In a real scenario we'd skip, but for bench we want to see parsing cost if it passed padding
            }

            if let Ok(ch) = ClientHello::try_from_slice(&payload) {
                // Check reputation
                let diff = reputation.calculate_difficulty(ip, false);
                reputation.record_violation(ip);

                // Process (generates cookie return)
                let _ = server.process_client_hello(&ch, diff, ip);
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_syn_flood);
criterion_main!(benches);
