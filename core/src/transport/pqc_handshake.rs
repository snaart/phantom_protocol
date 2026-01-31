//! Post-Quantum Secure Handshake Protocol
//!
//! Implements a secure handshake using hybrid cryptography:
//! - Key Exchange: X25519 + Kyber768 (hybrid KEM)
//! - Signatures: Ed25519 + Dilithium3 (hybrid sign)
//!
//! Protocol Flow:
//! 1. Client → Server: ClientHello { client_pk, client_verify_key }
//! 2. Server → Client: ServerHello { server_pk, ciphertext, signature }
//! 3. Both derive shared session key from KEM
//! 4. Session established with PQC-protected keys

use crate::crypto::hybrid_kem::{HybridSecretKey, HybridKeyPackage, HybridCiphertext};
use crate::crypto::hybrid_sign::{HybridSigningKey, HybridVerifyingKey, HybridSignature, HybridSignError};
use crate::crypto::pow::{PoWSolution, PoWChallenge};
use crate::transport::session::{Session, CryptoState};
use crate::transport::types::SessionId;
use crate::transport::scheduler::SchedulerMode;

use rkyv::{Archive, Deserialize, Serialize};
use bytecheck::CheckBytes;
use sha2::{Sha256, Digest};
use std::sync::Arc;

/// Client hello message (initiates handshake)
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct ClientHello {
    /// Client's hybrid public key for key exchange
    pub client_key_package: HybridKeyPackage,
    /// Client's hybrid verifying key for signatures
    pub client_verify_key: HybridVerifyingKey,
    /// Random nonce (32 bytes) for replay protection
    pub nonce: [u8; 32],
    /// Protocol version
    pub version: u8,
    /// Proof-of-Work solution (if required by server)
    pub pow_solution: Option<PoWSolution>,
}

/// Server response to ClientHello
#[derive(Debug)]
pub enum HandshakeResponse {
    Success(ServerHello, Session),
    Retry(HelloRetryRequest),
}

/// Hello Retry Request (Server demands PoW)
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct HelloRetryRequest {
    pub challenge: PoWChallenge,
}

/// Server hello message (response to ClientHello)
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct ServerHello {
    /// Server's hybrid public key
    pub server_key_package: HybridKeyPackage,
    /// Encapsulated secret (ciphertext for client)
    pub ciphertext: HybridCiphertext,
    /// Server's hybrid verifying key
    pub server_verify_key: HybridVerifyingKey,
    /// Signature over handshake transcript
    pub signature: HybridSignature,
    /// Session ID assigned by server
    pub session_id: [u8; 32],
}

/// Handshake transcript for signing
#[derive(Archive, Deserialize, Serialize)]
#[archive(check_bytes)]
struct HandshakeTranscript {
    client_nonce: [u8; 32],
    client_key_package: HybridKeyPackage,
    server_key_package: HybridKeyPackage,
    session_id: [u8; 32],
}

/// PQC Handshake state machine (server side)
pub struct PqcHandshakeServer {
    /// Server's KEM secret key
    kem_secret: HybridSecretKey,
    /// Server's KEM public key
    kem_public: HybridKeyPackage,
    /// Server's signing key
    signing_key: HybridSigningKey,
    /// Server's verifying key
    verifying_key: HybridVerifyingKey,
    /// Secret key for PoW HMAC
    pow_secret: [u8; 32],
}

impl PqcHandshakeServer {
    /// Create a new handshake server with fresh keys
    pub fn new() -> Self {
        let (kem_secret, kem_public) = HybridSecretKey::generate();
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        
        let mut pow_secret = [0u8; 32];
        getrandom::getrandom(&mut pow_secret).expect("Failed to generate PoW secret");
        
        Self {
            kem_secret,
            kem_public,
            signing_key,
            verifying_key,
            pow_secret,
        }
    }
    
    /// Create from existing keys
    pub fn with_keys(
        kem_secret: HybridSecretKey,
        kem_public: HybridKeyPackage,
        signing_key: HybridSigningKey,
        verifying_key: HybridVerifyingKey,
        pow_secret: [u8; 32],
    ) -> Self {
        Self { kem_secret, kem_public, signing_key, verifying_key, pow_secret }
    }
    
    /// Process ClientHello and generate ServerHello + Session
    pub fn process_client_hello(
        &self,
        client_hello: &ClientHello,
        difficulty: u8, // 0 to disable
        client_id: &[u8], // Bind challenge to client (e.g. IP address)
    ) -> Result<HandshakeResponse, HandshakeError> {
        // Validate version
        if client_hello.version != 1 {
            return Err(HandshakeError::UnsupportedVersion);
        }

        // Check PoW if difficulty > 0
        if difficulty > 0 {
            let valid = if let Some(sol) = &client_hello.pow_solution {
                // Verify solution and stateless challenge validity
                let challenge = PoWChallenge { 
                    nonce: sol.nonce, 
                    difficulty 
                };
                challenge.verify(sol, client_id, &self.pow_secret)
            } else {
                false
            };

            if !valid {
                let challenge = PoWChallenge::new_stateless(difficulty, client_id, &self.pow_secret);
                return Ok(HandshakeResponse::Retry(HelloRetryRequest { challenge }));
            }
        }
        
        // Encapsulate to client's public key
        let (shared_secret, ciphertext) = client_hello.client_key_package
            .encapsulate()
            .map_err(|e: anyhow::Error| HandshakeError::KemFailed(e.to_string()))?;
        
        // Generate session ID from shared secret + nonces
        let session_id_bytes = derive_session_id(&shared_secret, &client_hello.nonce);
        let session_id = SessionId::from_bytes(session_id_bytes);
        
        // Create transcript for signing
        let transcript = HandshakeTranscript {
            client_nonce: client_hello.nonce,
            client_key_package: client_hello.client_key_package.clone(),
            server_key_package: self.kem_public.clone(),
            session_id: session_id_bytes,
        };
        
        // Sign the transcript
        let transcript_bytes = transcript_to_bytes(&transcript);
        let signature = self.signing_key.sign(&transcript_bytes);
        
        // Create ServerHello
        let server_hello = ServerHello {
            server_key_package: self.kem_public.clone(),
            ciphertext,
            server_verify_key: self.verifying_key.clone(),
            signature,
            session_id: session_id_bytes,
        };
        
        // Create session with derived key
        let crypto = Arc::new(CryptoState::new(&shared_secret, &session_id));
        let session = Session::from_mls_derived(
            session_id,
            crypto,
            Some(shared_secret), // resumption secret
            SchedulerMode::LowLatency,
        );
        
        Ok(HandshakeResponse::Success(server_hello, session))
    }
    
    /// Get server's verifying key for clients to verify
    pub fn verifying_key(&self) -> &HybridVerifyingKey {
        &self.verifying_key
    }
}

impl Default for PqcHandshakeServer {
    fn default() -> Self {
        Self::new()
    }
}

/// PQC Handshake state machine (client side)
pub struct PqcHandshakeClient {
    /// Client's KEM secret key
    kem_secret: HybridSecretKey,
    /// Client's KEM public key
    kem_public: HybridKeyPackage,
    /// Client's signing key (for mutual auth)
    signing_key: HybridSigningKey,
    /// Client's verifying key
    verifying_key: HybridVerifyingKey,
    /// Generated nonce for this handshake
    nonce: [u8; 32],
}

impl PqcHandshakeClient {
    /// Create a new handshake client with fresh keys
    pub fn new() -> Self {
        let (kem_secret, kem_public) = HybridSecretKey::generate();
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        
        // Generate random nonce
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).expect("Failed to generate random nonce");
        
        Self {
            kem_secret,
            kem_public,
            signing_key,
            verifying_key,
            nonce,
        }
    }
    
    /// Generate ClientHello message
    pub fn create_client_hello(&self) -> ClientHello {
        ClientHello {
            client_key_package: self.kem_public.clone(),
            client_verify_key: self.verifying_key.clone(),
            nonce: self.nonce,
            version: 1,
            pow_solution: None,
        }
    }

    /// Update ClientHello with PoW solution
    pub fn update_hello_with_pow(&self, hello: &ClientHello, solution: PoWSolution) -> ClientHello {
        let mut new_hello = hello.clone();
        new_hello.pow_solution = Some(solution);
        new_hello
    }
    
    /// Process ServerHello and establish session
    pub fn process_server_hello(
        &self,
        server_hello: &ServerHello,
        expected_server_key: Option<&HybridVerifyingKey>,
    ) -> Result<Session, HandshakeError> {
        // Optionally verify server identity
        if let Some(expected) = expected_server_key {
            if expected != &server_hello.server_verify_key {
                return Err(HandshakeError::ServerIdentityMismatch);
            }
        }
        
        // Verify server signature
        let transcript = HandshakeTranscript {
            client_nonce: self.nonce,
            client_key_package: self.kem_public.clone(),
            server_key_package: server_hello.server_key_package.clone(),
            session_id: server_hello.session_id,
        };
        let transcript_bytes = transcript_to_bytes(&transcript);
        
        server_hello.server_verify_key
            .verify(&transcript_bytes, &server_hello.signature)
            .map_err(HandshakeError::SignatureVerificationFailed)?;
        
        // Decapsulate to get shared secret
        let shared_secret = self.kem_secret
            .decapsulate(&server_hello.ciphertext)
            .map_err(|e: anyhow::Error| HandshakeError::KemFailed(e.to_string()))?;
        
        // Verify session ID derivation
        let expected_session_id = derive_session_id(&shared_secret, &self.nonce);
        if expected_session_id != server_hello.session_id {
            return Err(HandshakeError::SessionIdMismatch);
        }
        
        // Create session
        let session_id = SessionId::from_bytes(server_hello.session_id);
        let crypto = Arc::new(CryptoState::new(&shared_secret, &session_id));
        let session = Session::from_mls_derived(
            session_id,
            crypto,
            Some(shared_secret),
            SchedulerMode::LowLatency,
        );
        
        Ok(session)
    }
}

impl Default for PqcHandshakeClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive session ID from shared secret and nonce
fn derive_session_id(shared_secret: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"phantom-session-id-v1");
    hasher.update(shared_secret);
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Serialize transcript for signing
fn transcript_to_bytes(transcript: &HandshakeTranscript) -> Vec<u8> {
    // Simple serialization (in production, use rkyv or similar)
    let mut out = Vec::new();
    out.extend_from_slice(&transcript.client_nonce);
    out.extend_from_slice(&transcript.client_key_package.x25519_pk);
    out.extend_from_slice(&transcript.client_key_package.kyber_pk);
    out.extend_from_slice(&transcript.server_key_package.x25519_pk);
    out.extend_from_slice(&transcript.server_key_package.kyber_pk);
    out.extend_from_slice(&transcript.session_id);
    out
}

/// Errors during PQC handshake
#[derive(Debug, Clone, thiserror::Error)]
pub enum HandshakeError {
    #[error("Unsupported protocol version")]
    UnsupportedVersion,
    
    #[error("KEM operation failed: {0}")]
    KemFailed(String),
    
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(HybridSignError),
    
    #[error("Server identity mismatch")]
    ServerIdentityMismatch,
    
    #[error("Session ID mismatch")]
    SessionIdMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_full_handshake() {
        // Server setup
        let server = PqcHandshakeServer::new();
        
        // Client setup
        let client = PqcHandshakeClient::new();
        
        // Client → Server: ClientHello
        let client_hello = client.create_client_hello();
        
        // Server processes and responds (difficulty 0)
        let result = server
            .process_client_hello(&client_hello, 0, &[0u8; 4])
            .expect("Server handshake failed");
            
        let (server_hello, server_session) = match result {
            HandshakeResponse::Success(h, s) => (h, s),
            _ => panic!("Expected success with difficulty 0"),
        };
        
        // Client processes ServerHello
        let client_session = client
            .process_server_hello(&server_hello, Some(server.verifying_key()))
            .expect("Client handshake failed");
        
        // Verify both sessions have the same encryption key
        let test_message = b"PQC handshake successful!";
        let encrypted = server_session.encrypt_packet(test_message).unwrap();
        let decrypted = client_session.decrypt_packet(&encrypted).unwrap();
        
        assert_eq!(test_message.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_handshake_with_pow() {
        let server = PqcHandshakeServer::new();
        let client = PqcHandshakeClient::new();
        let difficulty = 8; // Easy difficulty
        
        // 1. ClientHello (initial)
        let client_hello = client.create_client_hello();
        
        // 2. Server demands PoW
        let result = server.process_client_hello(&client_hello, difficulty, &[0u8; 4]).unwrap();
        
        let challenge = match result {
            HandshakeResponse::Retry(req) => req.challenge,
            _ => panic!("Expected Retry request"),
        };
        
        assert_eq!(challenge.difficulty, difficulty);
        
        // 3. Client solves PoW
        let solution = challenge.solve();
        
        // 4. Client resends ClientHello with solution
        let client_hello_pow = client.update_hello_with_pow(&client_hello, solution);
        
        // 5. Server accepts
        let result = server.process_client_hello(&client_hello_pow, difficulty, &[0u8; 4]).unwrap();
        
        assert!(matches!(result, HandshakeResponse::Success(_, _)));
    }
    
    #[test]
    fn test_handshake_without_pinned_key() {
        let server = PqcHandshakeServer::new();
        let client = PqcHandshakeClient::new();
        
        let client_hello = client.create_client_hello();
        let result = server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
        let (server_hello, _) = match result {
            HandshakeResponse::Success(h, s) => (h, s),
            _ => panic!("Expected success"),
        };
        
        // Accept any server key (TOFU - Trust On First Use)
        let client_session = client
            .process_server_hello(&server_hello, None)
            .expect("Handshake should succeed without pinned key");
        
        assert!(client_session.can_resume());
    }
    
    #[test]
    fn test_invalid_server_signature() {
        let server = PqcHandshakeServer::new();
        let client = PqcHandshakeClient::new();
        
        let client_hello = client.create_client_hello();
        let result = server.process_client_hello(&client_hello, 0, &[0u8; 4]).unwrap();
        let (mut server_hello, _) = match result {
            HandshakeResponse::Success(h, s) => (h, s),
            _ => panic!("Expected success"),
        };
        
        // Corrupt the signature
        server_hello.signature.ed25519_sig[0] ^= 0xFF;
        
        // Client should reject
        let result = client.process_server_hello(&server_hello, Some(server.verifying_key()));
        assert!(matches!(result, Err(HandshakeError::SignatureVerificationFailed(_))));
    }
}
