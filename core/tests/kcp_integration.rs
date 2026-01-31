//! KCP Integration Tests
//!
//! Tests KCP transport with real network connections using loopback.
//! These tests are marked #[ignore] as they may hang in some environments.

use kcp_tokio::{KcpConfig, async_kcp::{KcpListener, KcpStream}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use std::time::Duration;

/// Test basic KCP echo server/client
/// Run with: cargo test --test kcp_integration -- --ignored
#[tokio::test]
#[ignore = "May hang in CI; run manually with --ignored"]
async fn test_kcp_echo() {
    // Start echo server
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = KcpConfig::new().fast_mode();
    
    let mut listener = KcpListener::bind(server_addr, config.clone()).await.unwrap();
    let actual_addr = listener.local_addr();
    
    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let (mut stream, _addr) = listener.accept().await.unwrap();
        
        // Echo received data
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Connect client
    let mut client = KcpStream::connect(actual_addr, config).await.unwrap();
    
    // Send data
    let message = b"Hello KCP!";
    client.write_all(message).await.unwrap();
    client.flush().await.unwrap();
    
    // Receive echo
    let mut response = [0u8; 1024];
    let n = client.read(&mut response).await.unwrap();
    
    assert_eq!(&response[..n], message);
    
    // Clean up
    server_handle.await.unwrap();
}

/// Test KCP with length-prefixed framing
#[tokio::test]
#[ignore = "May hang in CI; run manually with --ignored"]
async fn test_kcp_length_prefixed() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = KcpConfig::new().turbo_mode();
    
    let mut listener = KcpListener::bind(server_addr, config.clone()).await.unwrap();
    let actual_addr = listener.local_addr();
    
    // Server with length-prefixed framing
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        
        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Read message
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await.unwrap();
        
        // Echo with length prefix
        stream.write_all(&len_buf).await.unwrap();
        stream.write_all(&msg).await.unwrap();
        stream.flush().await.unwrap();
    });
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let mut client = KcpStream::connect(actual_addr, config).await.unwrap();
    
    // Send with length prefix
    let message = b"Length-prefixed message";
    let len = message.len() as u32;
    client.write_all(&len.to_be_bytes()).await.unwrap();
    client.write_all(message).await.unwrap();
    client.flush().await.unwrap();
    
    // Read response with length prefix
    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await.unwrap();
    let response_len = u32::from_be_bytes(len_buf) as usize;
    
    let mut response = vec![0u8; response_len];
    client.read_exact(&mut response).await.unwrap();
    
    assert_eq!(response, message);
    
    server_handle.await.unwrap();
}

/// Test multiple concurrent connections
#[tokio::test]
#[ignore = "May hang in CI; run manually with --ignored"]
async fn test_kcp_concurrent_streams() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = KcpConfig::new().fast_mode();
    
    let mut listener = KcpListener::bind(server_addr, config.clone()).await.unwrap();
    let actual_addr = listener.local_addr();
    
    // Server handles multiple connections
    let server_handle = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                    let _ = stream.flush().await;
                }
            });
        }
    });
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Spawn multiple clients concurrently
    let mut handles = vec![];
    for i in 0..3 {
        let addr = actual_addr;
        let cfg = config.clone();
        handles.push(tokio::spawn(async move {
            let mut client = KcpStream::connect(addr, cfg).await.unwrap();
            
            let msg = format!("Client {}", i);
            client.write_all(msg.as_bytes()).await.unwrap();
            client.flush().await.unwrap();
            
            let mut buf = [0u8; 64];
            let n = client.read(&mut buf).await.unwrap();
            
            String::from_utf8_lossy(&buf[..n]).to_string()
        }));
    }
    
    // Verify all clients got their echoes
    for (i, handle) in handles.into_iter().enumerate() {
        let response = handle.await.unwrap();
        assert_eq!(response, format!("Client {}", i));
    }
    
    server_handle.await.unwrap();
}
