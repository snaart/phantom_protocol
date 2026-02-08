//! Unified Phantom Handshake Protocol
//!
//! Combines PQC security (Hybrid KEM/Sign) with Staged state machine 
//! for optimistic start, Early Data, and 0-RTT resumption.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use borsh::{BorshSerialize, BorshDeserialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use crate::crypto::hybrid_kem::{HybridSecretKey, HybridKeyPackage, HybridCiphertext};
use crate::crypto::hybrid_sign::{HybridSigningKey, HybridVerifyingKey, HybridSignature};
use crate::crypto::pow::{PoWSolution, PoWChallenge};
use crate::transport::session::{Session, CryptoState};
use crate::transport::types::{SessionId, SchedulerMode};
use crate::errors::CoreError;

/// Handshake processing stages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStage {
    /// Initial state, no messages exchanged
    Initial,
    /// Classical DH established, data can flow (Optimistic Start)
    ClassicalReady,
    /// Hybrid (PQC) established, session fully secure
    Established,
    /// Handshake failed
    Failed,
}

/// Client hello message (initiates handshake)
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ClientHello {
    /// hybrid public key for key exchange
    pub client_key_package: HybridKeyPackage,
    /// hybrid verifying key for signatures
    pub client_verify_key: HybridVerifyingKey,
    /// Random nonce (32 bytes) for replay protection
    pub nonce: [u8; 32],
    /// Protocol version
    pub version: u8,
    /// Stateless generic cookie to prove IP ownership
    pub cookie: Option<[u8; 32]>,
    /// Proof-of-Work solution (if required by server)
    pub pow_solution: Option<PoWSolution>,
    /// Optional session ID for 0-RTT resumption
    pub resume_session_id: Option<[u8; 32]>,
}

/// Server response to ClientHello
#[derive(Debug)]
pub enum HandshakeResponse {
    /// Success: Continue with ServerHello and Session
    Success(ServerHello, Session),
    /// Retry: Demand PoW or Cookie
    Retry(HelloRetryRequest),
    /// Fail: Handshake aborted
    Fail(HandshakeError),
}

/// Hello Retry Request (Server demands PoW or Cookie)
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HelloRetryRequest {
    pub challenge: Option<PoWChallenge>,
    pub cookie: Option<[u8; 32]>,
}

/// Server hello message (response to ClientHello)
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
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
#[derive(BorshSerialize)]
struct HandshakeTranscript<'a> {
    client_hello: &'a ClientHello,
    server_key_package: &'a HybridKeyPackage,
    ciphertext: &'a HybridCiphertext,
    server_verify_key: &'a HybridVerifyingKey,
    session_id: &'a [u8; 32],
}

fn compute_transcript_hash(transcript: &HandshakeTranscript) -> Result<[u8; 32], HandshakeError> {
    let mut hasher = Sha256::new();
    let bytes = borsh::to_vec(transcript)
        .map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

/// Handshake Server State Machine
///
/// Holds the server's long-lived signing key (via [`HybridSigningKey`], which
/// itself zeroes on drop) and the stateless PoW secret. On drop, `pow_secret`
/// is zeroed via the derived `ZeroizeOnDrop`.
#[derive(ZeroizeOnDrop)]
pub struct HandshakeServer {
    // SAFETY: `HybridSigningKey` has its own ZeroizeOnDrop. The wrapping field
    // is skipped here so the derive doesn't try to call `Zeroize::zeroize`
    // (which the inner type does not implement).
    #[zeroize(skip)]
    signing_key: HybridSigningKey,
    // Public material — never sensitive.
    #[zeroize(skip)]
    verifying_key: HybridVerifyingKey,
    pow_secret: [u8; 32],
}

impl HandshakeServer {
    pub fn new() -> Result<Self, HandshakeError> {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        
        let mut pow_secret = [0u8; 32];
        getrandom::getrandom(&mut pow_secret).map_err(|e| HandshakeError::RngError(e.to_string()))?;
        
        Ok(Self {
            signing_key,
            verifying_key,
            pow_secret,
        })
    }

    pub fn process_client_hello(
        &self,
        client_hello: &ClientHello,
        difficulty: u8,
        client_ip: IpAddr,
    ) -> HandshakeResponse {
        // 1. Version Check
        if client_hello.version != 1 {
            return HandshakeResponse::Fail(HandshakeError::UnsupportedVersion);
        }

        // 2. Stateless Checks (Cookie & PoW)
        let expected_cookie = match generate_cookie(&self.pow_secret, client_ip) {
            Ok(c) => c,
            Err(e) => return HandshakeResponse::Fail(e),
        };
        // Constant-time comparison: a non-CT `==` here leaks the cookie via
        // timing (an attacker would only need O(N) probes per byte instead of
        // 2^256). `subtle::ConstantTimeEq` is the standard remedy.
        let cookie_valid = client_hello
            .cookie
            .map(|c| bool::from(c.ct_eq(&expected_cookie)))
            .unwrap_or(false);
        
        let mut pow_valid = true;
        let mut challenge = None;
        if difficulty > 0 {
            if let Some(sol) = &client_hello.pow_solution {
                pow_valid = PoWChallenge { nonce: sol.nonce, difficulty }.verify(sol, client_ip.to_string().as_bytes(), &self.pow_secret);
            } else {
                pow_valid = false;
                challenge = Some(PoWChallenge::new_stateless(difficulty, client_ip.to_string().as_bytes(), &self.pow_secret));
            }
        }

        if !cookie_valid || !pow_valid {
            return HandshakeResponse::Retry(HelloRetryRequest {
                challenge,
                cookie: if !cookie_valid { Some(expected_cookie) } else { None },
            });
        }

        // 3. 0-RTT Resumption Check (Placeholder)
        // In a real implementation, we would look up the resume_session_id in a session cache
        
        // 4. Hybrid Key Exchange
        let result = client_hello.client_key_package.encapsulate();
        let (shared_secret, ciphertext) = match result {
            Ok(res) => res,
            Err(e) => return HandshakeResponse::Fail(HandshakeError::KemFailed(e.to_string())),
        };

        // Generate ephemeral keys for this connection
        let (_ephemeral_kem_secret, ephemeral_kem_public) = HybridSecretKey::generate();

        // 5. Session Derivation
        let session_id_bytes = derive_session_id(&shared_secret, &client_hello.nonce);
        let session_id = SessionId::from_bytes(session_id_bytes);

        // 6. Sign Transcript
        let transcript = HandshakeTranscript {
            client_hello,
            server_key_package: &ephemeral_kem_public,
            ciphertext: &ciphertext,
            server_verify_key: &self.verifying_key,
            session_id: &session_id_bytes,
        };
        let transcript_hash = match compute_transcript_hash(&transcript) {
            Ok(h) => h,
            Err(e) => return HandshakeResponse::Fail(e),
        };
        let signature = self.signing_key.sign(&transcript_hash);

        let server_hello = ServerHello {
            server_key_package: ephemeral_kem_public,
            ciphertext,
            server_verify_key: self.verifying_key.clone(),
            signature,
            session_id: session_id_bytes,
        };

        let crypto = match CryptoState::new(&shared_secret, true) {
            Ok(c) => c,
            Err(e) => return HandshakeResponse::Fail(HandshakeError::KemFailed(e.to_string())),
        };

        let session = Session::from_derived(session_id, crypto, SchedulerMode::LowLatency);
        
        // Derive resumption secret
        let mut resumption_secret = [0u8; 32];
        let hk = hkdf::Hkdf::<Sha256>::new(None, &shared_secret);
        if hk.expand(b"phantom-resumption-secret-v1", &mut resumption_secret).is_ok() {
            session.set_resumption_secret(resumption_secret);
        }

        HandshakeResponse::Success(server_hello, session)
    }

    pub fn verifying_key(&self) -> &HybridVerifyingKey {
        &self.verifying_key
    }
}

/// Handshake Client State Machine
///
/// `kem_secret` and `signing_key` are already `ZeroizeOnDrop` in their own
/// types. The remaining sensitive field is `nonce`, which is zeroed via the
/// derived `ZeroizeOnDrop`. `early_data` is application plaintext queued
/// before the secure channel is up — it lives in user-controlled storage and
/// is moved out by `take_early_data`.
#[derive(ZeroizeOnDrop)]
pub struct HandshakeClient {
    // SAFETY: each inner type has its own ZeroizeOnDrop / Drop that zeroes
    // sensitive bytes. Skipping at this layer avoids the derive trying to call
    // `Zeroize::zeroize` (which the inner types don't implement directly).
    #[zeroize(skip)]
    kem_secret: HybridSecretKey,
    #[zeroize(skip)]
    kem_public: HybridKeyPackage,
    #[zeroize(skip)]
    #[allow(dead_code)]
    signing_key: HybridSigningKey,
    #[zeroize(skip)]
    verifying_key: HybridVerifyingKey,
    nonce: [u8; 32],
    #[zeroize(skip)]
    early_data: RwLock<Vec<Vec<u8>>>,
    #[zeroize(skip)]
    stage: RwLock<HandshakeStage>,
}

impl HandshakeClient {
    /// Construct a client handshake state. Allocates an ephemeral hybrid KEM
    /// keypair, an ephemeral hybrid signing keypair, and a 32-byte client
    /// nonce. Returns `Err` if the OS RNG cannot be read.
    pub fn new() -> Result<Self, HandshakeError> {
        let (kem_secret, kem_public) = HybridSecretKey::generate();
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|e| HandshakeError::RngError(e.to_string()))?;

        Ok(Self {
            kem_secret,
            kem_public,
            signing_key,
            verifying_key,
            nonce,
            early_data: RwLock::new(Vec::new()),
            stage: RwLock::new(HandshakeStage::Initial),
        })
    }

    pub fn create_client_hello(&self) -> ClientHello {
        ClientHello {
            client_key_package: self.kem_public.clone(),
            client_verify_key: self.verifying_key.clone(),
            nonce: self.nonce,
            version: 1,
            cookie: None,
            pow_solution: None,
            resume_session_id: None,
        }
    }

    pub fn process_server_hello(
        &self,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
        expected_server_key: Option<&HybridVerifyingKey>,
    ) -> Result<Session, HandshakeError> {
        // 1. Verify Identity
        if let Some(expected) = expected_server_key {
            if expected != &server_hello.server_verify_key {
                return Err(HandshakeError::ServerIdentityMismatch);
            }
        }

        // 2. Verify Signature
        let transcript = HandshakeTranscript {
            client_hello,
            server_key_package: &server_hello.server_key_package,
            ciphertext: &server_hello.ciphertext,
            server_verify_key: &server_hello.server_verify_key,
            session_id: &server_hello.session_id,
        };
        let transcript_hash = compute_transcript_hash(&transcript)?;
        server_hello.server_verify_key.verify(&transcript_hash, &server_hello.signature)
            .map_err(|e| HandshakeError::KemFailed(format!("Signature check failed: {:?}", e)))?;

        // 3. Decapsulate
        let shared_secret = self.kem_secret.decapsulate(&server_hello.ciphertext)
            .map_err(|e| HandshakeError::KemFailed(e.to_string()))?;

        // 4. Create Session
        let session_id = SessionId::from_bytes(server_hello.session_id);
        let crypto = CryptoState::new(&shared_secret, false)
            .map_err(|e| HandshakeError::KemFailed(e.to_string()))?;

        let session = Session::from_derived(session_id, crypto, SchedulerMode::LowLatency);
        
        // 5. Derive resumption secret
        let mut resumption_secret = [0u8; 32];
        let hk = hkdf::Hkdf::<Sha256>::new(None, &shared_secret);
        if hk.expand(b"phantom-resumption-secret-v1", &mut resumption_secret).is_ok() {
            session.set_resumption_secret(resumption_secret);
        }

        *self.stage.write() = HandshakeStage::Established;
        Ok(session)
    }

    pub fn queue_early_data(&self, data: Vec<u8>) {
        self.early_data.write().push(data);
    }

    pub fn take_early_data(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.early_data.write())
    }

    pub fn stage(&self) -> HandshakeStage {
        *self.stage.read()
    }
}

/// Internal helper for session ID derivation
fn derive_session_id(shared_secret: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"phantom-session-id-v1");
    hasher.update(shared_secret);
    hasher.update(nonce);
    hasher.finalize().into()
}

fn generate_cookie(server_secret: &[u8; 32], ip: IpAddr) -> Result<[u8; 32], HandshakeError> {
    // SystemTime can be before UNIX_EPOCH only if the host clock is broken
    // backwards (e.g. mis-set RTC). Return a clear error instead of panicking
    // so DoS via malicious time configuration manifests as a handshake error,
    // not a process abort.
    let timestamp_min = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HandshakeError::ClockBackwards)?
        .as_secs()
        / 60;
    // HMAC-SHA-256 accepts any key length (longer keys are hashed). For our
    // fixed 32-byte secret this never fails, but we surface the error rather
    // than panic to keep the function total.
    let mut mac = Hmac::<Sha256>::new_from_slice(server_secret)
        .map_err(|e| HandshakeError::InternalError(format!("HMAC init: {}", e)))?;
    mac.update(ip.to_string().as_bytes());
    mac.update(&timestamp_min.to_be_bytes());
    let mut result = [0u8; 32];
    result.copy_from_slice(&mac.finalize().into_bytes());
    Ok(result)
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum HandshakeError {
    #[error("Unsupported version")]
    UnsupportedVersion,
    #[error("KEM failed: {0}")]
    KemFailed(String),
    #[error("Server identity mismatch")]
    ServerIdentityMismatch,
    #[error("RNG error: {0}")]
    RngError(String),
    #[error("serialization error during handshake: {0}")]
    SerializationError(String),
    #[error("system clock is before UNIX_EPOCH")]
    ClockBackwards,
    #[error("internal handshake error: {0}")]
    InternalError(String),
}

impl From<HandshakeError> for CoreError {
    fn from(err: HandshakeError) -> Self {
        CoreError::InternalError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unified_handshake() {
        let server = HandshakeServer::new().expect("HandshakeServer::new");
        let client = HandshakeClient::new().expect("HandshakeClient::new");
        let client_ip = "127.0.0.1".parse().expect("parse client_ip");

        // 1. Initial Hello
        let hello = client.create_client_hello();
        
        // 2. Server Retry (Cookie)
        let response = server.process_client_hello(&hello, 0, client_ip);
        let cookie = match response {
            HandshakeResponse::Retry(r) => r.cookie.unwrap(),
            _ => panic!("Expected retry"),
        };

        // 3. Retry with Cookie
        let mut hello_retry = hello.clone();
        hello_retry.cookie = Some(cookie);
        let response = server.process_client_hello(&hello_retry, 0, client_ip);

        let (server_hello, _server_session) = match response {
            HandshakeResponse::Success(h, s) => (h, s),
            _ => panic!("Expected success"),
        };

        // 4. Client Process
        let _client_session = client.process_server_hello(&hello_retry, &server_hello, Some(server.verifying_key())).unwrap();
        assert_eq!(*client.stage.read(), HandshakeStage::Established);
    }
}
