use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;
use tokio::net::TcpStream;
use tokio::sync::Mutex; 
use std::sync::Arc;
use crate::crypto::provider::{MlsProvider, new_provider, QuantumSigner, derive_psk_key};
use crate::network::framing::Framer;
use thiserror::Error;
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;
use zeroize::Zeroize;
use crate::network::tls;
use tokio_rustls::TlsConnector;
use rustls::ServerName;
use std::convert::TryFrom;
use crate::network::serialization;

static RT: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("Failed to create Tokio runtime")
});

#[derive(Debug, Error, uniffi::Error)]
pub enum PhantomError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Any error: {0}")]
    Generic(String),
}

impl From<anyhow::Error> for PhantomError {
    fn from(e: anyhow::Error) -> Self {
        PhantomError::Generic(e.to_string())
    }
}

impl From<std::io::Error> for PhantomError {
    fn from(e: std::io::Error) -> Self {
        PhantomError::Network(e.to_string())
    }
}

// Inner struct to hold mutable state
struct InnerClient {
    transport: tokio_rustls::client::TlsStream<TcpStream>,
    group_id: Vec<u8>,
    #[allow(dead_code)]
    identity: Vec<u8>,
    // E2EE State
    mls_group: Option<MlsGroup>,
    signer: Option<QuantumSigner>,
    // PSK Mode
    app_key: Vec<u8>,
}

impl Drop for InnerClient {
    fn drop(&mut self) {
        self.group_id.zeroize();
        self.identity.zeroize();
        self.app_key.zeroize();
    }
}

// Opaque Exported Object
#[derive(uniffi::Object)]
pub struct PhantomClient {
    inner: Arc<Mutex<InnerClient>>,
    #[allow(dead_code)]
    provider: MlsProvider,
}

#[uniffi::export]
impl PhantomClient {
    #[uniffi::constructor]
    pub async fn connect(addr: String, group_id: Vec<u8>, identity: Vec<u8>, server_ca_pem: Option<String>, shared_secret: Vec<u8>) -> Result<Arc<Self>, PhantomError> {
        let addr_clone = addr.clone();
        
        // Parse host from addr (e.g. "127.0.0.1:3001")
        let host_str = addr.split(':').next().unwrap_or("localhost");
        let domain = ServerName::try_from(host_str).map_err(|e| PhantomError::Generic(e.to_string()))?;
        
        let client_config = tls::configure_client_tls(server_ca_pem).map_err(|e| PhantomError::Generic(e.to_string()))?;
        let connector = TlsConnector::from(Arc::new(client_config));

        // Spawn connection logic
        let stream = RT.spawn(async move {
            let tcp = TcpStream::connect(addr_clone).await?;
            let tls_stream = connector.connect(domain, tcp).await?;
            Ok::<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error>(tls_stream)
        }).await.map_err(|e| PhantomError::Generic(e.to_string()))?
         .map_err(|e| PhantomError::Network(e.to_string()))?;
        
        // PSK Derivation for fallback mode
        let app_key = derive_psk_key(&group_id, &shared_secret)
            .map_err(|e| PhantomError::Crypto(e))?;
        
        // Initialize MLS Provider (memory-only storage)
        let provider = new_provider();
        
        // Generate signature keypair
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| PhantomError::Crypto(format!("SignatureKeyPair: {:?}", e)))?;
        
        // Store keys in provider
        signature_keys
            .store(provider.storage())
            .map_err(|e| PhantomError::Crypto(format!("Store keys: {:?}", e)))?;
            
        let signer = QuantumSigner::new(signature_keys.clone());

        let mut inner_client = InnerClient {
            transport: stream,
            group_id: group_id.clone(),
            identity: identity.clone(),
            mls_group: None,
            signer: Some(signer),
            app_key,
        };

        // Initialize Storage (local SQLite for persistence)
        let db_path = format!("phantom_client_{}.db", hex::encode(&inner_client.identity));
        let _storage = crate::storage::engine::StorageEngine::open(db_path, "secret_db_key")
            .map_err(|e| PhantomError::Generic(format!("Storage Init: {:?}", e)))?;
        
        // Try to load existing MLS group or create new one
        let gid: GroupId = GroupId::from_slice(&inner_client.group_id);
        
        // Check if group exists in storage
        if let Ok(group) = MlsGroup::load(provider.storage(), &gid) {
            println!("Loaded MLS Group from Provider!");
            inner_client.mls_group = Some(group);
        } else {
            println!("Creating new single-user group...");
            
            // Create credential
            let credential = BasicCredential::new(identity.clone());
            let credential_with_key = CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keys.to_public_vec().into(),
            };
            
            // Create MlsGroup using builder pattern
            let group = MlsGroup::builder()
                .ciphersuite(ciphersuite)
                .with_group_id(gid.clone())
                .build(&provider, &signature_keys, credential_with_key)
                .map_err(|e| PhantomError::Crypto(format!("MlsGroup build: {:?}", e)))?;
                
            inner_client.mls_group = Some(group);
        }

        Ok(Arc::new(Self {
            inner: Arc::new(Mutex::new(inner_client)),
            provider,
        }))
    }
}

// Non-exported impl for internal helpers
impl PhantomClient {
    pub async fn send_message(&self, msg: Vec<u8>) -> Result<(), PhantomError> {
        let inner_clone = self.inner.clone();
        let provider = self.provider.clone();
        
        RT.spawn(async move {
             let mut inner = inner_clone.lock().await;
             
             let signer_clone = inner.signer.clone();
             
             let final_payload = if let Some(group) = &mut inner.mls_group {
                 if let Some(signer) = &signer_clone {
                     let msg_out = group.create_message(&provider, signer, &msg)
                         .map_err(|e| PhantomError::Crypto(format!("{:?}", e)))?;
                     // Serialize using to_bytes()
                     msg_out.to_bytes()
                         .map_err(|e| PhantomError::Generic(format!("{:?}", e)))?
                 } else {
                     return Err(PhantomError::Generic("No signer available".into()));
                 }
             } else {
                 // PSK Mode (Fallback)
                 use rand::Rng;
                 let mut nonce = vec![0u8; 12];
                 rand::thread_rng().fill(&mut nonce[..]);
                 
                 use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
                 use chacha20poly1305::aead::{Aead, KeyInit};
                 
                 let key = Key::from_slice(&inner.app_key);
                 let cipher = ChaCha20Poly1305::new(key);
                 let nonce_ga = Nonce::from_slice(&nonce);
                 
                 let ct = cipher.encrypt(nonce_ga, msg.as_slice())
                    .map_err(|e| PhantomError::Crypto(format!("AEAD Encrypt: {:?}", e)))?;
                 
                 let mut pack = nonce;
                 pack.extend(ct);
                 pack
             };
             
             let auth_token = b"secret_token_123";
             let gid = inner.group_id.clone();
             Framer::write_frame(&mut inner.transport, &gid, 0, &final_payload, auth_token).await
                 .map_err(|e| PhantomError::Network(e.to_string()))?;
             Ok(())
        }).await.map_err(|e| PhantomError::Generic(e.to_string()))?
    }

    pub async fn recv_message(&self) -> Result<Vec<u8>, PhantomError> {
        let inner_clone = self.inner.clone();

        let payload = RT.spawn(async move {
            let mut inner = inner_clone.lock().await;
            let (_, _, payload, _) = Framer::read_frame(&mut inner.transport).await
                .map_err(|e| PhantomError::Network(e.to_string()))?;
        
            let payload_vec = payload.to_vec();
            
            // PSK Mode decryption
            if payload_vec.len() < 12 + 16 {
                return Err(PhantomError::Crypto("Received payload too short".into()));
            }
            
            let (nonce, ciphertext) = payload_vec.split_at(12);
            
            use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
            use chacha20poly1305::aead::{Aead, KeyInit};
            
            let key = Key::from_slice(&inner.app_key);
            let cipher = ChaCha20Poly1305::new(key);
            let nonce_ga = Nonce::from_slice(nonce);
            
            let plaintext = cipher.decrypt(nonce_ga, ciphertext)
                 .map_err(|_| PhantomError::Crypto("AEAD Decrypt Failed (Integrity Check)".into()))?;
                 
            Ok::<Vec<u8>, PhantomError>(plaintext)
        }).await.map_err(|e| PhantomError::Generic(e.to_string()))??;
         
        Ok(payload)
    }

    /// Generates a valid MLS KeyPackage and Identity.
    #[uniffi::method]
    pub fn generate_key_package_details(&self) -> Result<KeyPackageResult, PhantomError> {
         let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
         
         // Generate Signature Keypair
         let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
             .map_err(|e| PhantomError::Crypto(format!("SigKeyGen: {:?}", e)))?;
             
         // Derive Identity = Blake3(VK)
         let pk = signature_keys.to_public_vec();
         let identity = blake3::hash(&pk).as_bytes().to_vec();
         
         // Store keys
         signature_keys
             .store(self.provider.storage())
             .map_err(|e| PhantomError::Crypto(format!("Store: {:?}", e)))?;
         
         // Create Credential
         let credential = BasicCredential::new(identity.clone());
         let credential_with_key = CredentialWithKey {
             credential: credential.into(),
             signature_key: pk.clone().into(),
         };
         
         // Build KeyPackage
         let key_package = KeyPackage::builder()
             .build(
                 ciphersuite,
                 &self.provider,
                 &signature_keys,
                 credential_with_key,
             )
             .map_err(|e| PhantomError::Crypto(format!("KeyPackage Build: {:?}", e)))?;
             
         let kp_bytes = key_package.tls_serialize_detached()
             .map_err(|e| PhantomError::Crypto(format!("KP Serialize: {:?}", e)))?;
             
         Ok(KeyPackageResult {
             identity,
             key_package: kp_bytes,
             signing_key: signature_keys.private().to_vec(),
             verifying_key: pk,
         })
    }
    
    pub async fn add_member(&self, identity: Vec<u8>) -> Result<(), PhantomError> {
        // 1. Fetch KeyPackage
        let req = crate::network::control::ControlMessage::FetchKeyPackage { identity: identity.clone() };
        let req_bytes = serialization::serialize(&req)
            .map_err(|e| PhantomError::Generic(format!("Ser Req: {:?}", e)))?;
        
        let payload = {
            let mut inner = self.inner.lock().await;
            let zero_id = [0u8; 16];
            
            Framer::write_frame(&mut inner.transport, &zero_id, 0, &req_bytes, &[]).await
                .map_err(|e| PhantomError::Network(e.to_string()))?;
                
            let (gid, _, pay, _) = Framer::read_frame(&mut inner.transport).await
                .map_err(|e| PhantomError::Network(e.to_string()))?;
                
            if gid != zero_id {
                 return Err(PhantomError::Network("Protocol Mismatch".into()));
            }
            pay.to_vec()
        }; 
        
        let resp: crate::network::control::ControlMessage = serialization::deserialize(&payload)
            .map_err(|e| PhantomError::Generic(format!("Deserialize Resp: {:?}", e)))?;
            
        let key_package_bytes = match resp {
            crate::network::control::ControlMessage::KeyPackageResponse { key_package } => {
                key_package.ok_or(PhantomError::Generic("KeyPackage not found".into()))?
            },
            _ => return Err(PhantomError::Generic("Unexpected Response".into())),
        };
        
        // 2. Add Member
        let welcome_bytes = {
             let mut inner = self.inner.lock().await;
             
             let group = inner.mls_group.as_mut().ok_or(PhantomError::Generic("No Group Active".into()))?;
             let signer = inner.signer.as_ref().ok_or(PhantomError::Generic("No signer".into()))?;
             
             // Deserialize KeyPackage using MlsMessageIn
             let mls_msg = MlsMessageIn::tls_deserialize_exact(&key_package_bytes)
                 .map_err(|e| PhantomError::Crypto(format!("MlsMessageIn Deser: {:?}", e)))?;
             
             let kp = mls_msg.into_keypackage()
                 .map_err(|_| PhantomError::Crypto("Expected KeyPackage message".into()))?;
                 
             // Add member - returns (MlsMessageOut, MlsMessageOut/Welcome, Option<GroupInfo>)
             let (commit, welcome, _group_info) = group.add_members(&self.provider, signer, &[kp])
                 .map_err(|e| PhantomError::Crypto(format!("Add Members: {:?}", e)))?;
                 
             group.merge_pending_commit(&self.provider)
                  .map_err(|e| PhantomError::Crypto(format!("Merge Commit: {:?}", e)))?;
             
             // Serialize welcome
             welcome.to_bytes()
                 .map_err(|e| PhantomError::Crypto(format!("Ser Welcome: {:?}", e)))?
        };

        // 3. Upload Welcome
        let req = crate::network::control::ControlMessage::DeliverWelcome { 
             recipient_identity: identity,
             welcome_message: welcome_bytes,
        };
        let req_bytes = serialization::serialize(&req)
            .map_err(|e| PhantomError::Generic(format!("Ser Req: {:?}", e)))?;
            
        {
             let mut inner = self.inner.lock().await;
             let zero_id = [0u8; 16];
             Framer::write_frame(&mut inner.transport, &zero_id, 0, &req_bytes, &[]).await
                .map_err(|e| PhantomError::Network(e.to_string()))?;
        }

        Ok(())
    }

    pub async fn register(&self, kp: KeyPackageResult) -> Result<(), PhantomError> {
        // 1. Sign (Identity + KeyPackage)
        use openmls_traits::signatures::Signer;
        
        let signer = self.inner.lock().await.signer.clone()
            .ok_or(PhantomError::Generic("No signer".into()))?;
        
        let mut msg = Vec::new();
        msg.extend_from_slice(&kp.identity);
        msg.extend_from_slice(&kp.key_package);
        
        let signature = signer.sign(&msg)
            .map_err(|e| PhantomError::Crypto(format!("Sign Register: {:?}", e)))?;
            
        // 2. Send Control Message
        let req = crate::network::control::ControlMessage::Register {
            identity: kp.identity,
            key_package: kp.key_package,
            signature,
            verifying_key: kp.verifying_key,
        };
        
        let req_bytes = serialization::serialize(&req)
            .map_err(|e| PhantomError::Generic(format!("Ser Req: {:?}", e)))?;
            
        {
            let mut inner = self.inner.lock().await;
            let zero_id = [0u8; 16];
            Framer::write_frame(&mut inner.transport, &zero_id, 0, &req_bytes, &[]).await
                .map_err(|e| PhantomError::Network(e.to_string()))?;
        }
        
        Ok(())
    }

    pub async fn fetch_welcomes(&self, identity: Vec<u8>) -> Result<Vec<Vec<u8>>, PhantomError> {
        let req = crate::network::control::ControlMessage::FetchWelcome { identity };
        let req_bytes = serialization::serialize(&req)
            .map_err(|e| PhantomError::Generic(format!("Ser Req: {:?}", e)))?;
            
        let payload = {
            let mut inner = self.inner.lock().await;
            let zero_id = [0u8; 16];
            Framer::write_frame(&mut inner.transport, &zero_id, 0, &req_bytes, &[]).await
                .map_err(|e| PhantomError::Network(e.to_string()))?;
            
            let (gid, _, pay, _) = Framer::read_frame(&mut inner.transport).await
                .map_err(|e| PhantomError::Network(e.to_string()))?;
            if gid != zero_id {
                 return Err(PhantomError::Network("Protocol Mismatch".into()));
            }
            pay.to_vec()
        };
        
        let resp: crate::network::control::ControlMessage = serialization::deserialize(&payload)
            .map_err(|e| PhantomError::Generic(format!("Deserialize Resp: {:?}", e)))?;
            
        match resp {
            crate::network::control::ControlMessage::WelcomeResponse { welcomes } => Ok(welcomes),
             _ => Err(PhantomError::Generic("Unexpected Response".into())),
        }
    }

    pub async fn join_group(&self, welcome_bytes: Vec<u8>) -> Result<(), PhantomError> {
        // Deserialize Welcome using MlsMessageIn
        let mls_msg = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
            .map_err(|e| PhantomError::Crypto(format!("MlsMessageIn Deser: {:?}", e)))?;
            
        let welcome = mls_msg.into_welcome()
            .map_err(|_| PhantomError::Crypto("Expected Welcome message".into()))?;
        
        let mut inner = self.inner.lock().await;
        
        // Create join config
        let join_config = MlsGroupJoinConfig::default();
        
        // Stage the welcome
        let staged_welcome = StagedWelcome::new_from_welcome(
            &self.provider,
            &join_config,
            welcome,
            None, // RatchetTree if needed
        ).map_err(|e| PhantomError::Crypto(format!("Stage Welcome: {:?}", e)))?;
        
        // Convert to MlsGroup
        let group = staged_welcome.into_group(&self.provider)
            .map_err(|e| PhantomError::Crypto(format!("Into Group: {:?}", e)))?;
            
        // Update Inner State
        inner.group_id = group.group_id().as_slice().to_vec();
        inner.mls_group = Some(group);
        
        println!("Joined Group via Welcome! GroupID: {:?}", inner.group_id);
        
        Ok(())
    }
}

// Return type for FFI
#[derive(uniffi::Record)]
pub struct KeyPackageResult {
    pub identity: Vec<u8>,
    pub key_package: Vec<u8>,
    pub signing_key: Vec<u8>,
    pub verifying_key: Vec<u8>,
}
