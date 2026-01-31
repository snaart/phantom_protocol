use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};
use crate::errors::CoreError;
use crate::networks::transport::BoxedTransport;
use crate::networks::pipeline::Layer;
use crate::networks::engine::{NetworkEngine, EngineCommand};
use crate::networks::layers::MlsFramingLayer;
use crate::networks::tls;
use crate::provider::UniversalProvider;

// Import OpenMLS traits
use openmls::prelude::{KeyPackage, KeyPackageIn, ProtocolVersion};
use openmls_traits::OpenMlsProvider;
use tls_codec::Deserialize;

#[derive(Clone, Debug, uniffi::Record)]
pub struct KeyPackageResult {
    pub identity: Vec<u8>,
    pub key_package: Vec<u8>,
}

#[derive(Clone, uniffi::Object)]
pub struct PhantomClient {
    cmd_tx: mpsc::Sender<EngineCommand>,
    event_rx: Arc<broadcast::Sender<Vec<u8>>>,
    provider: UniversalProvider,
}

#[uniffi::export]
impl PhantomClient {
    #[uniffi::constructor]
    pub async fn connect(
        addr: String,
        group_id: Vec<u8>,
        _identity: Vec<u8>,
        server_ca_pem: Option<String>,
        shared_secret: Vec<u8>,
    ) -> Result<Arc<Self>, CoreError> {

        // 1. Setup Transport
        let tls_config = tls::configure_client_tls(server_ca_pem)
            .map_err(|e| CoreError::NetworkError(format!("TLS config error: {}", e)))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

        let stream = tokio::net::TcpStream::connect(&addr).await
            .map_err(|e| CoreError::NetworkError(format!("Connection failed: {}", e)))?;

        // SNI setup
        use rustls::pki_types::ServerName;
        let domain = ServerName::try_from("localhost")
            .map_err(|_| CoreError::NetworkError("Invalid server name".to_string()))?;

        let tls_stream = connector.connect(domain, stream).await
            .map_err(|e| CoreError::NetworkError(format!("TLS handshake failed: {}", e)))?;
        let transport: BoxedTransport = Box::new(tls_stream);

        // 2. Setup Layers
        let mut gid = [0u8; 16];
        if group_id.len() == 16 {
            gid.copy_from_slice(&group_id);
        }

        let framer = MlsFramingLayer {
            group_id: gid,
            epoch: 0,
            auth_token: shared_secret,
        };

        let layers: Vec<Box<dyn Layer>> = vec![Box::new(framer)];

        // 3. Start Engine
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (event_tx, _) = broadcast::channel(100);
        let event_tx_clone = event_tx.clone();

        let engine = NetworkEngine::new(transport, layers, cmd_rx, event_tx);
        tokio::spawn(engine.run());

        Ok(Arc::new(Self {
            cmd_tx,
            event_rx: Arc::new(event_tx_clone),
            provider: UniversalProvider::new(),
        }))
    }

    pub async fn send_message(&self, msg: Vec<u8>) -> Result<(), CoreError> {
        self.cmd_tx.send(EngineCommand::Send(msg)).await
            .map_err(|_| CoreError::NetworkError("Client disconnected".to_string()))
    }

    pub async fn recv_message(&self) -> Result<Vec<u8>, CoreError> {
        let mut rx = self.event_rx.subscribe();
        let msg = rx.recv().await
            .map_err(|e| CoreError::NetworkError(format!("Receive error: {}", e)))?;
        Ok(msg)
    }

    pub fn generate_key_package_details(&self) -> Result<KeyPackageResult, CoreError> {
        // Stub implementation
        Ok(KeyPackageResult {
            identity: vec![1, 2, 3],
            key_package: vec![4, 5, 6]
        })
    }

    /// Example of parsing KeyPackage in new OpenMLS version
    pub fn parse_key_package_example(&self, bytes: Vec<u8>) -> Result<(), CoreError> {
        let mut cursor = bytes.as_slice();

        // 1. Deserialize raw format (In)
        let kp_in = KeyPackageIn::tls_deserialize(&mut cursor)
            .map_err(|e| CoreError::SerializationError(format!("{:?}", e)))?;

        // 2. Validate signature (requires crypto provider)
        let _kp: KeyPackage = kp_in.validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| CoreError::MlsError(format!("Validation failed: {:?}", e)))?;

        Ok(())
    }
}