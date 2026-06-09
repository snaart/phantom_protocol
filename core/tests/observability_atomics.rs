//! Integration tests for `phantom_protocol::observability` lock-free atomics.
//!
//! Complements the unit tests inside `core/src/observability/atomics.rs` by
//! exercising the public `Observability` facade end-to-end (recording sites,
//! per-leg slicing, snapshot read consistency).

use phantom_protocol::observability::{Observability, ObservabilityConfig};
use phantom_protocol::transport::types::LegType;
use std::sync::Arc;

#[test]
fn per_leg_packet_counters_isolate_legs() {
    let obs = Observability::new(ObservabilityConfig::default());

    obs.record_send(1024, LegType::Tcp);
    obs.record_send(2048, LegType::Tcp);
    obs.record_send(512, LegType::Kcp);
    obs.record_send(256, LegType::FakeTls);
    obs.record_recv(800, LegType::Tcp);

    let s = obs.snapshot();
    assert_eq!(s.packets_sent, 4);
    assert_eq!(s.packets_recv, 1);
    assert_eq!(s.bytes_sent, 1024 + 2048 + 512 + 256);
    assert_eq!(s.bytes_recv, 800);

    // Per-leg breakdown survives the snapshot.
    let tcp_send = s
        .per_leg_packets
        .iter()
        .find(|(l, _, _)| *l == LegType::Tcp)
        .unwrap();
    assert_eq!(tcp_send.1, 2);
    assert_eq!(tcp_send.2, 1);
}

#[test]
fn handshake_counters_drive_snapshot() {
    let obs = Observability::new(ObservabilityConfig::default());
    obs.record_handshake_success(1_000_000); // 1 ms
    obs.record_handshake_success(5_000_000); // 5 ms
    obs.record_handshake_failure();

    let s = obs.snapshot();
    assert_eq!(s.handshakes_success, 2);
    assert_eq!(s.handshakes_failure, 1);
    assert_eq!(s.handshake_latency_count, 2);
    assert_eq!(s.handshake_latency_ns_sum, 6_000_000);
}

#[test]
fn concurrent_hot_path_recording_is_lock_free() {
    let obs = Observability::new(ObservabilityConfig::default());
    let obs_arc: Arc<Observability> = obs;

    let n_threads = 8;
    let iters = 25_000;
    let mut handles = Vec::with_capacity(n_threads);

    for _ in 0..n_threads {
        let obs2 = obs_arc.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..iters {
                obs2.record_send(64, LegType::Tcp);
                obs2.record_recv(64, LegType::Kcp);
                obs2.record_encrypt_ns(120);
                obs2.record_decrypt_ns(110);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    let s = obs_arc.snapshot();
    let expected = (n_threads * iters) as u64;
    assert_eq!(s.packets_sent, expected);
    assert_eq!(s.packets_recv, expected);
    assert_eq!(s.bytes_sent, expected * 64);
    assert_eq!(s.bytes_recv, expected * 64);
    assert_eq!(s.encrypt_count, expected);
    assert_eq!(s.decrypt_count, expected);
}

#[test]
fn namespace_prefix_is_honored() {
    let cfg = ObservabilityConfig::builder().namespace("custom").build();
    let obs = Observability::new(cfg);
    assert_eq!(obs.config().namespace.as_ref(), "custom");
}

#[test]
fn snapshot_reflects_session_and_stream_gauges() {
    let obs = Observability::new(ObservabilityConfig::default());
    obs.session_opened(LegType::Tcp);
    obs.session_opened(LegType::Tcp);
    obs.session_opened(LegType::Kcp);
    obs.session_closed(LegType::Kcp);

    obs.stream_opened();
    obs.stream_opened();
    obs.stream_opened();
    obs.stream_closed();

    let s = obs.snapshot();
    assert_eq!(s.active_sessions, 2);
    assert_eq!(s.active_streams, 2);
}
