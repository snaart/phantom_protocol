use tokio::net::TcpListener;
use anyhow::Result;
use log::{info, error};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use phantom_core::networks::tls;

mod db;
mod network;

use db::Db;
use network::SharedState;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let dsn = std::env::var("DATABASE_URL").unwrap_or("postgres://user:pass@localhost:5432/phantom".to_string());
    let db = match Db::new(&dsn).await {
        Ok(d) => Some(d),
        Err(e) => {
            log::warn!("Failed to connect to DB: {}. Running in DEMO MODE (No Persistence).", e);
            None
        }
    };
    
    // TLS Setup
    let (server_config, cert_pem) = tls::configure_server_tls()?;
    
    // Save Cert for PINNING TESTS
    std::fs::write("server.crt", cert_pem).expect("Failed to write server.crt");
    
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    
    let state = SharedState::new();
    
    let addr = "0.0.0.0:3001";
    let listener = TcpListener::bind(addr).await?;
    info!("Quantum Rust Teapot Server listening on {} (TLS Enabled)", addr);
    
    loop {
        let (socket, _) = listener.accept().await?;
        let db = db.clone();
        let state = state.clone();
        let acceptor = acceptor.clone();
        
        let remote_addr = match socket.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to get peer address: {}", e);
                continue;
            }
        };
        
        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(tls_stream) => {
                     // Pass the TLS stream to handle_connection
                     // Note: We need to change handle_connection sig or box it.
                     // handle_connection takes TcpStream. We will change it to take Generic AsyncRead+Write
                     if let Err(e) = network::handle_connection(tls_stream, remote_addr.ip(), db, state).await {
                        error!("Handler error: {}", e);
                     }
                }
                Err(e) => error!("TLS Accept error: {}", e),
            }
        });
    }
}
