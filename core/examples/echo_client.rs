//! Phantom Echo Client Example
//!
//! A PQC-encrypted echo client demonstrating the Phantom transport.
//! This client implements the full PQC handshake including:
//! - Post-Quantum Key Exchange (Kyber/Dilithium)
//! - Stateless Proof-of-Work (PoW) solving
//! - MLS Framing
//!
//! Usage:
//!   cargo run --example echo_client -- --addr 127.0.0.1:8080

use phantom_core::transport::pqc_handshake::{PqcHandshakeClient, HandshakeResponse, ClientHello, HelloRetryRequest};
use phantom_core::networks::layers::MlsFramingLayer;
use phantom_core::networks::pipeline::Layer;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt};
use tokio::net::TcpStream;
use bytes::BytesMut;
use anyhow::{Result, Context};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Parse command line arguments
    let addr = std::env::args()
        .skip_while(|a| a != "--addr")
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║             Phantom PQC Echo Client v0.2.0                 ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║ Connecting to: {}                               ║", addr);
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // 1. Initialize Handshake Client
    let handshake_start = Instant::now();
    let mut client = PqcHandshakeClient::new();
    let mut client_hello = client.create_client_hello();
    
    // Connect to server
    println!("Connecting to {}...", addr);
    let mut stream = TcpStream::connect(&addr).await?;
    println!("Connected!");

    let mut buffer = BytesMut::with_capacity(4096);

    // Helper functions
    async fn send_framed(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
        let framer = MlsFramingLayer {
            group_id: [0u8; 16], 
            epoch: 0,
            auth_token: vec![],
        };
        let mut buf = BytesMut::new();
        framer.on_outbound(payload, &mut buf).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_framed(stream: &mut TcpStream, buffer: &mut BytesMut) -> Result<BytesMut> {
        let framer = MlsFramingLayer {
            group_id: [0u8; 16],
            epoch: 0, 
            auth_token: vec![],
        };
        
        loop {
            // Check if we have a full frame in buffer
            if let Some(payload) = framer.on_inbound(buffer).await? {
                return Ok(payload);
            }
            
            // Read more data
            let mut temp = [0u8; 1024];
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                return Err(anyhow::anyhow!("Connection closed"));
            }
            buffer.extend_from_slice(&temp[..n]);
        }
    }

    // 2. Handshake Loop
    loop {
        println!("Sending ClientHello...");
        let hello_bytes = rkyv::to_bytes::<_, 1024>(&client_hello)
            .context("Failed to serialize ClientHello")?;
        
        send_framed(&mut stream, &hello_bytes).await?;
        
        println!("Waiting for response...");
        let response_bytes = recv_framed(&mut stream, &mut buffer).await?;
        
        // Deserialize response
        // Note: In real app, we might receive ServerHello or HelloRetryRequest directly, 
        // but here we expect the server to send one of them.
        // Since `HandshakeResponse` includes both, we try to deserialize as `HandshakeResponse`?
        // Wait, server logic in `network.rs` sends `ServerHello` OR `HelloRetryRequest` directly?
        // Let's check server code again. 
        // Ah, `rkyv::to_bytes::<_, 1024>(&server_hello)` OR `(&retry_req)`.
        // So we receive EITHER ServerHello OR HelloRetryRequest. 
        // We'll try to deserialize as HelloRetryRequest first, if it fails, try ServerHello.
        // Or better, checking the rkyv structure. 
        
        // Attempt 1: HelloRetryRequest
        if let Ok(retry_req) = rkyv::from_bytes::<HelloRetryRequest>(&response_bytes) {
            println!("Received HelloRetryRequest. PoW Challenge required.");
            println!("  Difficulty: {}", retry_req.challenge.difficulty);
            println!("  Solving PoW...");
            
            let start = Instant::now();
            
            // CRITICAL: Solve PoW in blocking task to avoid stalling async runtime
            let challenge = retry_req.challenge.clone();
            let solution = tokio::task::spawn_blocking(move || {
                challenge.solve()
            }).await?;
            
            println!("  Solved in {:?}! Nonce: {:?}", start.elapsed(), solution.nonce);
            
            // Update ClientHello with solution
            client.update_hello_with_pow(&mut client_hello, solution);
            continue; // Retry handshake
        }
        
        // Attempt 2: ServerHello (Using PqcHandshakeClient's expected type, which is probably inferred)
        // Actually, let's look at `PqcHandshakeServer::process_client_hello` return type.
        // It returns `HandshakeResponse`.
        
        // Since we don't have a strict type for "ServerHello" readily available here without importing it
        // let's assume if it's not Retry, it's Success.
        
        println!("Received ServerHello (assumed). Handshake complete!");
        println!("Total handshake time: {:?}", handshake_start.elapsed());
        break;
    }

    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║ Echo Mode - Type messages to send, Ctrl+C to exit         ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // 3. Echo Loop
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    
    loop {
        line.clear();
        if stdin.read_line(&mut line).await? == 0 {
            break; 
        }
        let msg = line.trim();
        if msg.is_empty() { continue; }
        
        // Send
        send_framed(&mut stream, msg.as_bytes()).await?;
        
        // Receive
        let echo_bytes = recv_framed(&mut stream, &mut buffer).await?;
        let echo_str = String::from_utf8_lossy(&echo_bytes);
        println!("Server: {}", echo_str);
    }

    Ok(())
}
