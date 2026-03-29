//! Unified Phantom Handshake Protocol
//!
//! Combines PQC security (Hybrid KEM/Sign) with Staged state machine
//! for optimistic start, Early Data, and 0-RTT resumption.

use borsh::{BorshDeserialize, BorshSerialize};
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use crate::crypto::hybrid_kem::{HybridCiphertext, HybridKeyPackage, HybridSecretKey};
use crate::crypto::hybrid_sign::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::crypto::pow::{PoWChallenge, PoWSolution};
use crate::errors::CoreError;
use crate::transport::session::{CryptoState, Session};
use crate::transport::types::{SchedulerMode, SessionId};

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
    let bytes =
        borsh::to_vec(transcript).map_err(|e| HandshakeError::SerializationError(e.to_string()))?;
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

/// Handshake Server State Machine
///
/// Holds the server's long-lived signing key (via [`HybridSigningKey`], which
/// itself zeroes on drop) and a *master* secret from which the actually-used
/// per-hour PoW/cookie secret is derived on each call (see
/// [`derive_session_secret_for_hour`]). On drop the master is zeroed via the
/// derived `ZeroizeOnDrop`.
///
/// Rotation (Phase 1.11): the master itself rotates only on process restart,
/// but the derived hour-bucketed secret rotates every hour. Validation
/// accepts the current hour and the immediately-previous hour, so a cookie
/// or PoW solution captured at minute 59 of one hour is still honored at
/// minute 5 of the next.
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
    master_secret: [u8; 32],
    /// Adaptive-difficulty counters (Phase 1.14). Atomics so they are
    /// thread-safe for the concurrent `accept()` path; not secret, hence
    /// `#[zeroize(skip)]`.
    #[zeroize(skip)]
    handshakes_this_minute: AtomicU64,
    #[zeroize(skip)]
    minute_start_unix_sec: AtomicU64,
}

impl HandshakeServer {
    pub fn new() -> Result<Self, HandshakeError> {
        let (signing_key, verifying_key) = HybridSigningKey::generate();

        let mut master_secret = [0u8; 32];
        getrandom::getrandom(&mut master_secret)
            .map_err(|e| HandshakeError::RngError(e.to_string()))?;

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            signing_key,
            verifying_key,
            master_secret,
            handshakes_this_minute: AtomicU64::new(0),
            minute_start_unix_sec: AtomicU64::new(now_sec),
        })
    }

    /// Increment the per-minute handshake-count counter and roll over the
    /// minute window if necessary. Called at the start of every
    /// `process_client_hello`.
    fn record_handshake(&self) {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let start = self.minute_start_unix_sec.load(Ordering::Relaxed);
        if now_sec.saturating_sub(start) >= 60 {
            // Reset the bucket. Racing other threads here is acceptable —
            // multiple resets within a single boundary just under-count by a
            // few; the next minute is unaffected.
            self.handshakes_this_minute.store(0, Ordering::Relaxed);
            self.minute_start_unix_sec.store(now_sec, Ordering::Relaxed);
        }
        self.handshakes_this_minute.fetch_add(1, Ordering::Relaxed);
    }

    /// Recommended PoW difficulty for the current handshake load. Callers
    /// (e.g. `PhantomListener::accept`) pass this into `process_client_hello`
    /// so the cost imposed on each new client scales with server load.
    ///
    /// Difficulty tiers (handshakes-per-minute → difficulty):
    /// ```text
    ///   <100         → 0   (no PoW)
    ///   100..500     → 4   (~16 hash evaluations expected)
    ///   500..2000    → 8   (~256 evaluations)
    ///   2000..10000  → 12  (~4k evaluations)
    ///   >=10000      → 16  (~64k evaluations)
    /// ```
    /// These tiers err on the side of leniency: a healthy server doing a few
    /// hundred handshakes per minute imposes no PoW work on clients. Only at
    /// high load — where DoS protection matters most — does the cost ramp up.
    pub fn adaptive_difficulty(&self) -> u8 {
        let count = self.handshakes_this_minute.load(Ordering::Relaxed);
        match count {
            0..=99 => 0,
            100..=499 => 4,
            500..=1999 => 8,
            2000..=9999 => 12,
            _ => 16,
        }
    }

    /// Current per-minute handshake count. Exposed for metrics
    /// (`handshakes_per_minute`).
    pub fn handshakes_this_minute(&self) -> u64 {
        self.handshakes_this_minute.load(Ordering::Relaxed)
    }

    #[tracing::instrument(
        name = "phantom.handshake.process_client_hello",
        skip_all,
        fields(
            client_ip = %client_ip,
            difficulty = difficulty,
            has_cookie = client_hello.cookie.is_some(),
            has_pow = client_hello.pow_solution.is_some(),
            resume = client_hello.resume_session_id.is_some(),
        ),
    )]
    pub fn process_client_hello(
        &self,
        client_hello: &ClientHello,
        difficulty: u8,
        client_ip: IpAddr,
    ) -> HandshakeResponse {
        // Phase 1.14: tally this call before any work is done, so the
        // load counter reflects attempts (including the rejected ones).
        self.record_handshake();

        // 1. Version negotiation (Phase 1.8).
        //
        // Two wire formats are currently defined: V1 (stable) and V2
        // (rekey + multi-path + coalescing — see PROTOCOL.md § 11).
        // Downgrade resistance: `client_hello.version` is borsh-serialized
        // into the `HandshakeTranscript` that the server signs, so a
        // network attacker rewriting the byte forces a transcript-signature
        // mismatch on the client side. The server simply accepts what the
        // client offers and binds it into the signature.
        //
        // V3+ rejection here keeps the surface narrow.
        if !matches!(client_hello.version, 1 | 2) {
            return HandshakeResponse::Fail(HandshakeError::UnsupportedVersion);
        }

        // 2. Stateless Checks (Cookie & PoW)
        //
        // Cookie freshness (Phase 1.10): `validate_cookie` accepts the current
        // bucket OR the immediately-previous bucket (5-minute buckets, so
        // 5-10 min effective validity). Comparisons are constant-time.
        let cookie_valid = match client_hello.cookie {
            Some(c) => match validate_cookie(&self.master_secret, client_ip, &c) {
                Ok(v) => v,
                Err(e) => return HandshakeResponse::Fail(e),
            },
            None => false,
        };
        // Pre-compute a fresh cookie to hand to the client on a retry.
        let expected_cookie = match generate_cookie(&self.master_secret, client_ip) {
            Ok(c) => c,
            Err(e) => return HandshakeResponse::Fail(e),
        };

        let mut pow_valid = true;
        let mut challenge = None;
        if difficulty > 0 {
            // PoW verification (Phase 1.11): the derived hour-bucketed secret
            // rotates every `SECRET_ROTATION_SECONDS`. Accept either the
            // current or the previous hour's derivation so a client that
            // computed a solution just before the rotation boundary doesn't
            // have to redo the work.
            let cur_hour = match current_secret_hour() {
                Ok(h) => h,
                Err(e) => return HandshakeResponse::Fail(e),
            };
            let prev_hour = cur_hour.saturating_sub(1);
            let hours: &[u64] = if cur_hour == prev_hour {
                &[cur_hour]
            } else {
                &[cur_hour, prev_hour]
            };

            if let Some(sol) = &client_hello.pow_solution {
                let mut any_valid = false;
                for &h in hours {
                    let derived = match derive_session_secret_for_hour(&self.master_secret, h) {
                        Ok(s) => s,
                        Err(e) => return HandshakeResponse::Fail(e),
                    };
                    let challenge_ref = PoWChallenge {
                        nonce: sol.nonce,
                        difficulty,
                    };
                    if challenge_ref.verify(sol, client_ip.to_string().as_bytes(), &derived) {
                        any_valid = true;
                        break;
                    }
                }
                pow_valid = any_valid;
            } else {
                pow_valid = false;
                let derived = match derive_session_secret_for_hour(&self.master_secret, cur_hour) {
                    Ok(s) => s,
                    Err(e) => return HandshakeResponse::Fail(e),
                };
                challenge = Some(PoWChallenge::new_stateless(
                    difficulty,
                    client_ip.to_string().as_bytes(),
                    &derived,
                ));
            }
        }

        if !cookie_valid || !pow_valid {
            return HandshakeResponse::Retry(HelloRetryRequest {
                challenge,
                cookie: if !cookie_valid {
                    Some(expected_cookie)
                } else {
                    None
                },
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

        // Generate a per-session ephemeral hybrid KEM keypair. The public half
        // is bound into the transcript signature (defense-in-depth: commits
        // the server to a session-specific value beyond `session_id` and the
        // client's nonce). The secret half is intentionally discarded — the
        // current protocol does not perform a second KEM round trip using it.
        //
        // TODO(phase 4.1, 0-RTT): when 0-RTT lands, either consume the secret
        // for the post-handshake KEM upgrade or remove this field from the
        // wire (which requires bumping `VersionedPacket` to V2).
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

        // is_server=true and traffic_secret=shared_secret seed the rekey
        // chain (Phase 1.5) so the server can later derive forward.
        let session = Session::from_derived(
            session_id,
            crypto,
            SchedulerMode::LowLatency,
            shared_secret,
            true,
        );
        // Phase 1.8: bind the negotiated wire version. `client_hello.version`
        // is transcript-bound (the signature covers the whole ClientHello),
        // so a wire-level downgrade attempt is detected by the client.
        session.set_wire_version(client_hello.version);

        // Derive resumption secret
        let mut resumption_secret = [0u8; 32];
        let hk = hkdf::Hkdf::<Sha256>::new(None, &shared_secret);
        if hk
            .expand(b"phantom-resumption-secret-v1", &mut resumption_secret)
            .is_ok()
        {
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

    /// Default `ClientHello` offers wire-format **V2**. V2 has been
    /// negotiable since Phase 1.8 (server accepts {1, 2}); the data
    /// pump V2-routes since the 4.2 / 2.5 closeout commit.
    /// Downgrade resistance comes from the transcript signature over
    /// `client_hello.version` — see `docs/migration/v1-to-v2.md`.
    pub fn create_client_hello(&self) -> ClientHello {
        self.create_client_hello_with_version(2)
    }

    /// Like [`create_client_hello`](Self::create_client_hello) but offers
    /// a specific wire-format version. Accepted values: `1` (V1, the
    /// safe default) and `2` (V2 — widened flags, rekey epoch in
    /// header, path id). Rust-only; not on the UniFFI surface because
    /// most callers stay on the default.
    ///
    /// The wire version is signed under the handshake transcript, so a
    /// network-level rewrite of this byte aborts the handshake at the
    /// client-side signature verification step (Phase 1.8 downgrade
    /// resistance).
    pub fn create_client_hello_with_version(&self, version: u8) -> ClientHello {
        ClientHello {
            client_key_package: self.kem_public.clone(),
            client_verify_key: self.verifying_key.clone(),
            nonce: self.nonce,
            version,
            cookie: None,
            pow_solution: None,
            resume_session_id: None,
        }
    }

    #[tracing::instrument(
        name = "phantom.handshake.process_server_hello",
        skip_all,
        fields(
            pinned = expected_server_key.is_some(),
        ),
    )]
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
        server_hello
            .server_verify_key
            .verify(&transcript_hash, &server_hello.signature)
            .map_err(|e| HandshakeError::KemFailed(format!("Signature check failed: {:?}", e)))?;

        // 3. Decapsulate
        let shared_secret = self
            .kem_secret
            .decapsulate(&server_hello.ciphertext)
            .map_err(|e| HandshakeError::KemFailed(e.to_string()))?;

        // 4. Create Session
        let session_id = SessionId::from_bytes(server_hello.session_id);
        let crypto = CryptoState::new(&shared_secret, false)
            .map_err(|e| HandshakeError::KemFailed(e.to_string()))?;

        // is_server=false and traffic_secret=shared_secret seed the rekey
        // chain (Phase 1.5) so the client can later derive forward in lock-
        // step with the server.
        let session = Session::from_derived(
            session_id,
            crypto,
            SchedulerMode::LowLatency,
            shared_secret,
            false,
        );
        // Phase 1.8: the wire version the client offered is exactly the
        // one the server bound into the transcript signature; a
        // network downgrade would have failed signature verification
        // above. Setting it here keeps both ends in sync.
        session.set_wire_version(client_hello.version);

        // 5. Derive resumption secret
        let mut resumption_secret = [0u8; 32];
        let hk = hkdf::Hkdf::<Sha256>::new(None, &shared_secret);
        if hk
            .expand(b"phantom-resumption-secret-v1", &mut resumption_secret)
            .is_ok()
        {
            session.set_resumption_secret(resumption_secret);
        }

        *self.stage.write() = HandshakeStage::Established;
        Ok(session)
    }

    /// Queue a plaintext payload to be sent as early-data once the secure
    /// channel is up.
    ///
    /// NOTE: Early-data is currently queued at the API layer (see
    /// `PhantomSession::send_queue`) and the data-pump flushes it through the
    /// regular AEAD path after the handshake completes. This per-handshake
    /// buffer is reserved for the future 0-RTT path (Phase 4.1).
    pub fn queue_early_data(&self, data: Vec<u8>) {
        self.early_data.write().push(data);
    }

    /// Drain the queued early-data buffer. See [`queue_early_data`] — the
    /// production `send_queue` path is currently used instead; this hook is
    /// reserved for 0-RTT.
    #[allow(dead_code)]
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

/// Bucket size in seconds for the rolling cookie salt.
///
/// Cookies are valid for the current bucket and the previous bucket — so the
/// effective validity window is between `COOKIE_BUCKET_SECONDS` and
/// `2 * COOKIE_BUCKET_SECONDS` depending on when within the bucket the cookie
/// was minted.
const COOKIE_BUCKET_SECONDS: u64 = 300;

/// Rotation interval in seconds for the derived per-hour PoW/cookie secret.
/// The master_secret in `HandshakeServer` only rotates on process restart;
/// this constant controls the cadence of the derived sub-secret.
const SECRET_ROTATION_SECONDS: u64 = 3600;

fn current_cookie_bucket() -> Result<u64, HandshakeError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HandshakeError::ClockBackwards)?
        .as_secs()
        / COOKIE_BUCKET_SECONDS)
}

fn current_secret_hour() -> Result<u64, HandshakeError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HandshakeError::ClockBackwards)?
        .as_secs()
        / SECRET_ROTATION_SECONDS)
}

/// HKDF-derive a fresh sub-secret from `master` for the given hour bucket.
/// The same master + hour always produces the same derived secret, so this
/// is just a deterministic function of (master, hour) — no internal state.
pub(crate) fn derive_session_secret_for_hour(
    master: &[u8; 32],
    hour: u64,
) -> Result<[u8; 32], HandshakeError> {
    let hk = hkdf::Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    let mut info = Vec::with_capacity(16 + 8);
    info.extend_from_slice(b"phantom-pow-cookie-v1");
    info.extend_from_slice(&hour.to_be_bytes());
    hk.expand(&info, &mut out)
        .map_err(|e| HandshakeError::InternalError(format!("HKDF expand: {}", e)))?;
    Ok(out)
}

fn generate_cookie_for_bucket(
    derived_secret: &[u8; 32],
    ip: IpAddr,
    bucket: u64,
) -> Result<[u8; 32], HandshakeError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(derived_secret)
        .map_err(|e| HandshakeError::InternalError(format!("HMAC init: {}", e)))?;
    mac.update(ip.to_string().as_bytes());
    mac.update(&bucket.to_be_bytes());
    let mut result = [0u8; 32];
    result.copy_from_slice(&mac.finalize().into_bytes());
    Ok(result)
}

fn generate_cookie(master: &[u8; 32], ip: IpAddr) -> Result<[u8; 32], HandshakeError> {
    let hour = current_secret_hour()?;
    let derived = derive_session_secret_for_hour(master, hour)?;
    generate_cookie_for_bucket(&derived, ip, current_cookie_bucket()?)
}

/// Validate a client-supplied cookie against the 2x2 combinations of
/// (current/previous hour) × (current/previous bucket). All comparisons are
/// constant-time via [`subtle::ConstantTimeEq`], and the accept signal is
/// accumulated as a [`subtle::Choice`] so the function never branches on
/// any individual comparison's outcome.
fn validate_cookie(
    master: &[u8; 32],
    ip: IpAddr,
    cookie: &[u8; 32],
) -> Result<bool, HandshakeError> {
    let bucket = current_cookie_bucket()?;
    let hour = current_secret_hour()?;
    let prev_bucket = bucket.saturating_sub(1);
    let prev_hour = hour.saturating_sub(1);

    let bucket_candidates: [u64; 2] = if bucket == prev_bucket {
        [bucket, bucket]
    } else {
        [bucket, prev_bucket]
    };
    let hour_candidates: [u64; 2] = if hour == prev_hour {
        [hour, hour]
    } else {
        [hour, prev_hour]
    };

    let mut accept = subtle::Choice::from(0u8);
    for h in hour_candidates {
        let derived = derive_session_secret_for_hour(master, h)?;
        for b in bucket_candidates {
            let expected = generate_cookie_for_bucket(&derived, ip, b)?;
            accept |= cookie.ct_eq(&expected);
        }
    }
    Ok(bool::from(accept))
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
        let _client_session = client
            .process_server_hello(&hello_retry, &server_hello, Some(server.verifying_key()))
            .unwrap();
        assert_eq!(*client.stage.read(), HandshakeStage::Established);
    }
}
