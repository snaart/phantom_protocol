//! High-Performance Optimized Benchmark v2
//!
//! Phase 1: Pure AES-GCM throughput (alloc vs in-place)
//! Phase 2: TCP Streaming (1GB unidirectional) — Raw vs TLS vs Phantom
//! Phase 3: UDP with Coalescing vs per-packet
//! Summary table with all results

use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::runtime::Runtime;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use phantom_core::crypto::aes_session::AesSession;
use phantom_core::transport::packet_coalescer::{PacketCoalescer, Decoalescer, CoalescerConfig};

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║    PHANTOM TRANSPORT v2 — High-Performance Benchmark        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let rt = Runtime::new().unwrap();

    // ─── Phase 1: Pure crypto ────────────────────────────────────────
    println!("═══════════════════════════════════════════════════════════════");
    println!("  PHASE 1: PURE AES-256-GCM (ring, HW accelerated)");
    println!("═══════════════════════════════════════════════════════════════\n");

    let session = AesSession::from_shared_secret(&[0xAB; 32]);
    for &size in &[1024, 16384, 65536] {
        let data = vec![0xCDu8; size];
        let iters = if size <= 1024 { 200_000 } else { 50_000 };
        let start = Instant::now();
        for _ in 0..iters {
            let e = session.encrypt(&data).unwrap();
            std::hint::black_box(e);
        }
        let tput = mib(size, iters, start.elapsed());
        println!("  {:>6}: {:>7.0} MiB/s", fmt(size), tput);
    }
    println!();

    // ─── Phase 2: TCP Streaming (unidirectional, 512MB) ─────────────
    println!("═══════════════════════════════════════════════════════════════");
    println!("  PHASE 2: TCP STREAMING (512 MB, unidirectional)");
    println!("═══════════════════════════════════════════════════════════════\n");

    let total_bytes: usize = 512 * 1024 * 1024; // 512 MB
    let chunk_size: usize = 64 * 1024; // 64 KB chunks

    let tcp_s  = rt.block_on(bench_tcp_stream(total_bytes, chunk_size));
    let tls_s  = rt.block_on(bench_tls_stream(total_bytes, chunk_size));
    let phan_s = rt.block_on(bench_phantom_tcp_stream(total_bytes, chunk_size));

    println!("  Raw TCP:             {:>8.1} MiB/s", tcp_s);
    println!("  TLS 1.3:             {:>8.1} MiB/s", tls_s);
    println!("  Phantom AES+TCP:     {:>8.1} MiB/s  ← PQ-safe", phan_s);
    println!("  Phantom vs TLS:      {:>8.2}x", phan_s / tls_s);
    println!();

    // ─── Phase 3: UDP — per-packet vs coalesced ─────────────────────
    println!("═══════════════════════════════════════════════════════════════");
    println!("  PHASE 3: UDP — PER-PACKET vs COALESCED (1KB × 50K)");
    println!("═══════════════════════════════════════════════════════════════\n");

    let udp_size = 1024;
    let udp_count = 50_000;

    let (raw_mb, raw_pps)  = rt.block_on(bench_raw_udp(udp_size, udp_count));
    let (ph_mb, ph_pps)    = rt.block_on(bench_phantom_udp(udp_size, udp_count));
    let (co_mb, co_pps, co_ratio) = rt.block_on(bench_phantom_udp_coalesced(udp_size, udp_count));

    println!("  Raw UDP (per-pkt):   {:>7.1} MiB/s  ({:>5.0}K pps)", raw_mb, raw_pps / 1000.0);
    println!("  Phantom UDP:         {:>7.1} MiB/s  ({:>5.0}K pps)  ← AES-GCM", ph_mb, ph_pps / 1000.0);
    println!("  Phantom Coalesced:   {:>7.1} MiB/s  ({:>5.0}K pps)  ← batched", co_mb, co_pps / 1000.0);
    println!("  Coalesc. ratio:      {:.0} pkts/datagram", co_ratio);
    println!();

    // ─── Summary ─────────────────────────────────────────────────────
    println!("═══════════════════════════════════════════════════════════════");
    println!("  ИТОГОВАЯ ТАБЛИЦА");
    println!("═══════════════════════════════════════════════════════════════\n");
    let vs_tls = |x: f64| x / tls_s;
    println!("  ┌──────────────────────────┬──────────────┬────────┬──────────┐");
    println!("  │ Протокол                 │  Throughput  │ vs TLS │ PQ-Safe  │");
    println!("  ├──────────────────────────┼──────────────┼────────┼──────────┤");
    println!("  │ Raw TCP                  │ {:>8.1} MB/s │   -    │   ❌     │", tcp_s);
    println!("  │ TLS 1.3                  │ {:>8.1} MB/s │ 1.00x  │   ❌     │", tls_s);
    println!("  │ Phantom AES+TCP          │ {:>8.1} MB/s │ {:.2}x  │   ✅     │", phan_s, vs_tls(phan_s));
    println!("  │ Raw UDP (per-packet)     │ {:>8.1} MB/s │ {:.2}x  │   ❌     │", raw_mb, vs_tls(raw_mb));
    println!("  │ Phantom UDP              │ {:>8.1} MB/s │ {:.2}x  │   ✅     │", ph_mb, vs_tls(ph_mb));
    println!("  │ Phantom UDP (coalesced)  │ {:>8.1} MB/s │ {:.2}x  │   ✅     │", co_mb, vs_tls(co_mb));
    println!("  └──────────────────────────┴──────────────┴────────┴──────────┘");
    println!();
    println!("  Crypto: PQC (Kyber768+Dilithium3) → ring AES-256-GCM (HW)");
    println!("  Platform: Apple M1 Pro, ARM FEAT_AES");
}

// ─────────────────────────────────────────────────────────────────────────────
fn mib(size: usize, iters: usize, d: std::time::Duration) -> f64 {
    (size * iters) as f64 / 1_048_576.0 / d.as_secs_f64()
}

fn fmt(n: usize) -> String {
    if n >= 1_048_576 { format!("{}MB", n / 1_048_576) }
    else if n >= 1024 { format!("{}KB", n / 1024) }
    else { format!("{}B", n) }
}

fn gen_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (vec![CertificateDer::from(c.cert.der().to_vec())],
     PrivateKeyDer::try_from(c.key_pair.serialize_der()).unwrap())
}

// ─── TCP Streaming ─────────────────────────────────────────────────────────
async fn bench_tcp_stream(total: usize, chunk: usize) -> f64 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let t = total;
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.set_nodelay(true).ok();
        let mut buf = vec![0u8; chunk];
        let mut read = 0;
        while read < t { read += s.read(&mut buf).await.unwrap_or(0); }
    });
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.set_nodelay(true).ok();
    let data = vec![0xABu8; chunk];
    let t = Instant::now();
    let mut sent = 0;
    while sent < total { c.write_all(&data).await.unwrap(); sent += chunk; }
    let el = t.elapsed();
    total as f64 / 1_048_576.0 / el.as_secs_f64()
}

// ─── TLS Streaming ─────────────────────────────────────────────────────────
async fn bench_tls_stream(total: usize, chunk: usize) -> f64 {
    let (certs, key) = gen_cert();
    let sc = rustls::ServerConfig::builder().with_no_client_auth()
        .with_single_cert(certs.clone(), key).unwrap();
    let acc = TlsAcceptor::from(Arc::new(sc));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ct = total;
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tcp.set_nodelay(true).ok();
        let mut tls = acc.accept(tcp).await.unwrap();
        let mut buf = vec![0u8; chunk];
        let mut read = 0;
        while read < ct { read += tls.read(&mut buf).await.unwrap_or(0); }
    });
    let mut root = rustls::RootCertStore::empty();
    root.add(certs[0].clone()).unwrap();
    let cc = rustls::ClientConfig::builder()
        .with_root_certificates(root).with_no_client_auth();
    let conn = TlsConnector::from(Arc::new(cc));
    let tcp = TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).ok();
    let mut tls = conn.connect("localhost".try_into().unwrap(), tcp).await.unwrap();
    let data = vec![0xABu8; chunk];
    let t = Instant::now();
    let mut sent = 0;
    while sent < total { tls.write_all(&data).await.unwrap(); sent += chunk; }
    let el = t.elapsed();
    total as f64 / 1_048_576.0 / el.as_secs_f64()
}

// ─── Phantom TCP Streaming ─────────────────────────────────────────────────
async fn bench_phantom_tcp_stream(total: usize, chunk: usize) -> f64 {
    let secret = [0xAB; 32];
    let cs = Arc::new(AesSession::from_shared_secret(&secret));
    let ss = Arc::new(AesSession::from_shared_secret_peer(&secret));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ct = total;
    let ss2 = ss.clone();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        tcp.set_nodelay(true).ok();
        let mut lb = [0u8; 4];
        let mut read_total = 0;
        while read_total < ct {
            if tcp.read_exact(&mut lb).await.is_err() { break; }
            let len = u32::from_be_bytes(lb) as usize;
            let mut ct = vec![0u8; len];
            if tcp.read_exact(&mut ct).await.is_err() { break; }
            let pt = ss2.decrypt_in_place(&mut ct).unwrap();
            read_total += pt.len();
        }
    });

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).ok();
    let data = vec![0xABu8; chunk];
    let t = Instant::now();
    let mut sent = 0;
    while sent < total {
        let mut ct = data.clone();
        cs.encrypt_in_place(&mut ct).unwrap();
        let l = (ct.len() as u32).to_be_bytes();
        tcp.write_all(&l).await.unwrap();
        tcp.write_all(&ct).await.unwrap();
        sent += chunk;
    }
    let el = t.elapsed();
    total as f64 / 1_048_576.0 / el.as_secs_f64()
}

// ─── Raw UDP ───────────────────────────────────────────────────────────────
async fn bench_raw_udp(size: usize, count: usize) -> (f64, f64) {
    let srv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sa = srv.local_addr().unwrap();
    let s2 = srv.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        for _ in 0..count { s2.recv(&mut buf).await.ok(); }
    });
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli.connect(sa).await.unwrap();
    let data = vec![0xABu8; size];
    let t = Instant::now();
    for _ in 0..count { cli.send(&data).await.unwrap(); }
    let el = t.elapsed();
    let mb = (size * count) as f64 / 1_048_576.0 / el.as_secs_f64();
    (mb, count as f64 / el.as_secs_f64())
}

// ─── Phantom UDP (per-packet) ──────────────────────────────────────────────
async fn bench_phantom_udp(size: usize, count: usize) -> (f64, f64) {
    let cs = Arc::new(AesSession::from_shared_secret(&[0xAB; 32]));
    let srv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sa = srv.local_addr().unwrap();
    let s2 = srv.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        for _ in 0..count { s2.recv(&mut buf).await.ok(); }
    });
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli.connect(sa).await.unwrap();
    let data = vec![0xABu8; size];
    let t = Instant::now();
    for _ in 0..count {
        let mut ct = data.clone();
        cs.encrypt_in_place(&mut ct).unwrap();
        cli.send(&ct).await.unwrap();
    }
    let el = t.elapsed();
    let mb = (size * count) as f64 / 1_048_576.0 / el.as_secs_f64();
    (mb, count as f64 / el.as_secs_f64())
}

// ─── Phantom UDP (coalesced) ───────────────────────────────────────────────
async fn bench_phantom_udp_coalesced(size: usize, count: usize) -> (f64, f64, f64) {
    let cs = Arc::new(AesSession::from_shared_secret(&[0xAB; 32]));
    let srv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sa = srv.local_addr().unwrap();
    let s2 = srv.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match s2.recv(&mut buf).await {
                Ok(_) => {},
                Err(_) => break,
            }
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cli.connect(sa).await.unwrap();
    let data = vec![0xABu8; size];
    let config = CoalescerConfig {
        max_datagram_size: 8192,  // Safe for macOS localhost UDP
        max_packets: 7,           // 7 × 1KB ≈ 7KB per datagram
        flush_timeout_us: 100,
    };
    let mut coalescer = PacketCoalescer::new(config);
    let mut datagrams_sent: usize = 0;
    let t = Instant::now();
    for _ in 0..count {
        if let Some(mut batch) = coalescer.push(&data) {
            // Encrypt the whole batch as one unit
            cs.encrypt_in_place(&mut batch).unwrap();
            cli.send(&batch).await.unwrap();
            datagrams_sent += 1;
        }
    }
    if let Some(mut batch) = coalescer.flush() {
        cs.encrypt_in_place(&mut batch).unwrap();
        cli.send(&batch).await.unwrap();
        datagrams_sent += 1;
    }
    let el = t.elapsed();
    let mb = (size * count) as f64 / 1_048_576.0 / el.as_secs_f64();
    let pps = count as f64 / el.as_secs_f64();
    let ratio = count as f64 / datagrams_sent as f64;
    (mb, pps, ratio)
}
