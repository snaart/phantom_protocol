use crate::api::session::{PhantomSession, SessionTransport};
use crate::api::tcp_transport::TcpSessionTransport;
use crate::errors::CoreError;
use crate::transport::handshake::{
    ClientHello, HandshakeResponse, HandshakeServer,
};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(uniffi::Object)]
pub struct PhantomListener {
    listener: Mutex<TcpListener>,
    handshake_server: Arc<HandshakeServer>,
}

#[uniffi::export]
impl PhantomListener {
    #[uniffi::constructor]
    pub async fn bind(addr: String) -> Result<Arc<Self>, CoreError> {
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        let hs = HandshakeServer::new()
            .map_err(|e| CoreError::InternalError(e.to_string()))?;
        Ok(Arc::new(Self {
            listener: Mutex::new(listener),
            handshake_server: Arc::new(hs),
        }))
    }

    /// The server's long-lived hybrid verifying key, serialized via
    /// `HybridVerifyingKey::to_bytes`. Clients MUST pin this value before
    /// completing a handshake to defeat MITM (see Vuln 1 in security review).
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.handshake_server.verifying_key().to_bytes()
    }

    pub async fn accept(&self) -> Result<Arc<PhantomSession>, CoreError> {
        let (stream, peer) = self
            .listener
            .lock()
            .await
            .accept()
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        let transport = TcpSessionTransport::new(stream);
        let server_session =
            drive_server_handshake(&transport, &self.handshake_server, peer.ip()).await?;
        Ok(PhantomSession::from_accepted_server_session(
            peer.to_string(),
            transport,
            Arc::new(server_session),
        ))
    }
}

/// Drive the server side of the Phantom hybrid PQC handshake on a freshly
/// accepted transport, handling the optional cookie / PoW retry round.
async fn drive_server_handshake(
    transport: &TcpSessionTransport,
    hs: &HandshakeServer,
    client_ip: IpAddr,
) -> Result<crate::transport::session::Session, CoreError> {
    loop {
        let hello_bytes = transport.recv_bytes().await?;
        let hello = borsh::from_slice::<ClientHello>(&hello_bytes).map_err(|e| {
            CoreError::NetworkError(format!("ClientHello parse failed: {}", e))
        })?;
        match hs.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let bytes = borsh::to_vec(&retry).map_err(|e| {
                    CoreError::NetworkError(format!("Retry encode failed: {}", e))
                })?;
                transport.send_bytes(&bytes).await?;
                // Loop back and read the retried hello.
            }
            HandshakeResponse::Success(server_hello, session) => {
                let bytes = borsh::to_vec(&server_hello).map_err(|e| {
                    CoreError::NetworkError(format!("ServerHello encode failed: {}", e))
                })?;
                transport.send_bytes(&bytes).await?;
                return Ok(session);
            }
            HandshakeResponse::Fail(e) => {
                return Err(CoreError::InternalError(format!(
                    "handshake rejected: {}",
                    e
                )));
            }
        }
    }
}
