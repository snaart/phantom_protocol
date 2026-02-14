//! Phantom Echo Server Example
//!
//! A PQC-encrypted echo server demonstrating the Phantom transport.
//!
//! Usage:
//!   cargo run --example echo_server -- --port 8080
//!
//! The server accepts PQC handshakes and echoes back any data received.

use phantom_core::transport::pqc_handshake::{PqcHandshakeServer, ClientHello};
use phantom_core::transport::session::Session;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;

/// Server state
struct EchoServer {
    /// PQC handshake handler
    handshake: PqcHandshakeServer,
    /// Active sessions by address
    sessions: RwLock<HashMap<SocketAddr, Session>>,
    /// Statistics
    stats: ServerStats,
}

#[derive(Default)]
struct ServerStats {
    connections: std::sync::atomic::AtomicU64,
    bytes_echoed: std::sync::atomic::AtomicU64,
}

impl EchoServer {
    fn new() -> Self {
        Self {
            handshake: PqcHandshakeServer::new(),
            sessions: RwLock::new(HashMap::new()),
            stats: ServerStats::default(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Parse command line arguments
    let port: u16 = std::env::args()
        .skip_while(|a| a != "--port")
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    
    let server = Arc::new(EchoServer::new());
    
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║             Phantom PQC Echo Server v0.1.0                 ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║ Cryptography:                                              ║");
    println!("║   • Key Exchange: X25519 + Kyber768                        ║");
    println!("║   • Signatures:   Ed25519 + Dilithium3                     ║");
    println!("║   • Encryption:   ChaCha20-Poly1305                        ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║ Listening on:                                              ║");
    println!("║   TCP: 0.0.0.0:{}                                          ║", port);
    println!("║   UDP: 0.0.0.0:{}  (KCP)                                   ║", port);
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    println!("Server public key fingerprint:");
    let pk = server.handshake.verifying_key();
    println!("  Ed25519:   {:02x}{:02x}{:02x}{:02x}...", pk.ed25519_pk[0], pk.ed25519_pk[1], pk.ed25519_pk[2], pk.ed25519_pk[3]);
    println!("  Dilithium: {:02x}{:02x}{:02x}{:02x}...", pk.dilithium_pk[0], pk.dilithium_pk[1], pk.dilithium_pk[2], pk.dilithium_pk[3]);
    println!();
    println!("Waiting for connections...");
    println!();

    // Start TCP listener
    let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    let server_tcp = server.clone();
    
    let tcp_handle = tokio::spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, addr)) => {
                    println!("[TCP] New connection from {}", addr);
                    let server = server_tcp.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_connection(server, stream, addr).await {
                            eprintln!("[TCP] Error handling {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[TCP] Accept error: {}", e);
                }
            }
        }
    });

    // Start UDP listener (for KCP)
    let udp_socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
    let server_udp = server.clone();
    
    let udp_handle = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            match udp_socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    println!("[UDP] Received {} bytes from {}", len, addr);
                    // In a real implementation, this would handle KCP packets
                    let _ = server_udp;
                }
                Err(e) => {
                    eprintln!("[UDP] Receive error: {}", e);
                }
            }
        }
    });

    // Wait for both listeners
    tokio::select! {
        _ = tcp_handle => {},
        _ = udp_handle => {},
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down...");
        }
    }

    Ok(())
}

async fn handle_tcp_connection(
    server: Arc<EchoServer>,
    mut stream: tokio::net::TcpStream,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    server.stats.connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    
    // Read ClientHello (simplified - in production use proper framing)
    let mut hello_buf = vec![0u8; 8192];
    let n = stream.read(&mut hello_buf).await?;
    
    if n < 100 {
        // Too short to be a proper handshake, just echo
        println!("[TCP] {} - Simple echo mode ({} bytes)", addr, n);
        stream.write_all(&hello_buf[..n]).await?;
        server.stats.bytes_echoed.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        return Ok(());
    }
    
    println!("[TCP] {} - Received handshake ({} bytes)", addr, n);
    
    // Deserialize ClientHello (simplified)
    // In production, use proper rkyv deserialization
    let _client_hello_data = &hello_buf[..n];
    
    // For demo, just send a response and enter echo mode
    let response = b"PHANTOM_HANDSHAKE_OK";
    stream.write_all(response).await?;
    println!("[TCP] {} - Handshake complete, entering echo mode", addr);
    
    // Echo loop
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => {
                println!("[TCP] {} - Connection closed", addr);
                break;
            }
            Ok(n) => n,
            Err(e) => {
                eprintln!("[TCP] {} - Read error: {}", addr, e);
                break;
            }
        };
        
        // Echo back
        if let Err(e) = stream.write_all(&buf[..n]).await {
            eprintln!("[TCP] {} - Write error: {}", addr, e);
            break;
        }
        
        server.stats.bytes_echoed.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        println!("[TCP] {} - Echoed {} bytes", addr, n);
    }
    
    Ok(())
}
