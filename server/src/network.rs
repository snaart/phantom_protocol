use std::sync::Arc;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, RwLock};
use std::collections::HashMap;
use anyhow::Result;
use log::{info, error};
use bytes::BytesMut;

use phantom_core::networks::pipeline::Layer;
use phantom_core::networks::layers::MlsFramingLayer;
use crate::db::Db;

// SharedState remains similar...
pub struct SharedState {
    pub groups: RwLock<HashMap<Vec<u8>, broadcast::Sender<Vec<u8>>>>,
    pub ip_tracker: RwLock<HashMap<IpAddr, (u32, std::time::Instant)>>,
}

impl SharedState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            groups: RwLock::new(HashMap::new()),
            ip_tracker: RwLock::new(HashMap::new()),
        })
    }
    // ... methods check_rate_limit, get_or_create_tx ...
}

// Новая версия хендлера с использованием слоев
pub async fn handle_connection<S>(mut stream: S, peer_ip: IpAddr, db: Option<Db>, state: Arc<SharedState>) -> Result<()>
where S: AsyncRead + AsyncWrite + Unpin + Send
{
    // 1. Initial Handshake / Read Header
    let mut buffer = BytesMut::with_capacity(4096);
    let mut temp_buf = [0u8; 1024];

    use phantom_core::transport::pqc_handshake::{PqcHandshakeServer, ClientHello, HandshakeResponse, HelloRetryRequest};
    use rkyv::Deserialize;

    // Handshake Loop (for PoW Retry)
    let handshake_server = PqcHandshakeServer::new();
    let difficulty = 8; // Configure difficulty here

    // Reuse buffer and framer for outbound messages
    let mut out_buf = BytesMut::with_capacity(1024);
    let framer = MlsFramingLayer {
        group_id: [0u8; 16], 
        epoch: 0,
        auth_token: vec![],
    };

    loop {
        // Mock Framer to extract payload
        // Note: For inbound we use a fresh framer instance or reset state if needed, 
        // but since MlsFramingLayer here is stateless for handshake (epoch 0), we can just use a local one.
        // However, to keep it clean and match previous logic for inbound:
        let inbound_framer = MlsFramingLayer {
            group_id: [0u8; 16], 
            epoch: 0,
            auth_token: vec![],
        };

        // Parse frame - Try to get frame from existing buffer
        // framer.on_inbound advances the buffer if frame is found
        let payload = match inbound_framer.on_inbound(&mut buffer).await? {
            Some(p) => p,
            None => {
                 // Frame incomplete, read more data
                 let n = tokio::io::AsyncReadExt::read(&mut stream, &mut temp_buf).await?;
                 if n == 0 { return Ok(()); } // EOF
                 buffer.extend_from_slice(&temp_buf[0..n]);
                 continue; // Try parsing again
            }
        };

        // Deserialize ClientHello (Safe version with validation)
        // Stealth: If invalid, do not return error immediately. Blackhole the connection.
        // We map_err to () effectively dropping the complex rkyv error which is !Send
        let client_hello_res = rkyv::from_bytes(&payload).map_err(|_| ());

        let client_hello: ClientHello = match client_hello_res {
            Ok(hello) => hello,
            Err(_) => {
                error!("Invalid ClientHello from {}. Stealth mode: ignoring/draining.", peer_ip);
                // Stealth: Drain socket until closed by client, BUT limit time to avoid Slowloris
                let mut drain = [0u8; 1024];
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        match tokio::io::AsyncReadExt::read(&mut stream, &mut drain).await {
                            Ok(0) => break, // EOF
                            Ok(_) => continue, // Ignore data
                            Err(_) => break, // Error
                        }
                    }
                }).await;
                return Ok(());
            }
        };

        // Process Handshake
        let client_id = match peer_ip {
             std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
             std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };

        match handshake_server.process_client_hello(&client_hello, difficulty, &client_id)? {
            HandshakeResponse::Success(server_hello, _session) => {
                info!("PQC Handshake Success! Session established.");
                
                // Serialize ServerHello
                let resp_bytes = rkyv::to_bytes::<_, 1024>(&server_hello).unwrap();
                
                // Reuse Framer and buffer
                out_buf.clear();
                framer.on_outbound(&resp_bytes, &mut out_buf).await?;
                
                // Send framed data
                tokio::io::AsyncWriteExt::write_all(&mut stream, &out_buf).await?;
                
                // Transition to Session Loop
                break;
            }
            HandshakeResponse::Retry(retry_req) => {
                info!("PoW required. Sending HelloRetryRequest.");
                
                // Serialize HelloRetryRequest
                let resp_bytes = rkyv::to_bytes::<_, 1024>(&retry_req).unwrap();
                
                // Reuse Framer and buffer
                out_buf.clear();
                framer.on_outbound(&resp_bytes, &mut out_buf).await?;
                
                tokio::io::AsyncWriteExt::write_all(&mut stream, &out_buf).await?;
                
                // DO NOT clear buffer here. Loop continues.
                // If client already sent the next frame (ClientHello + Proof), it is in buffer.
                // Next iteration will pick it up or read more data if needed.
            }
        }
    }

    Ok(())
}