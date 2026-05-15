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

use crate::crypto::adaptive_crypto::{CipherSuite, CryptoSession};
use crate::crypto::hybrid_kem::{HybridCiphertext, HybridKeyPackage, HybridSecretKey};
use crate::crypto::hybrid_sign::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::crypto::kdf::derive_early_data_keying;
use crate::crypto::pow::{PoWChallenge, PoWSolution};
use crate::errors::CoreError;
use crate::transport::session::{CryptoState, Session};
use crate::transport::session_cache::SessionCache;
use crate::transport::types::{SchedulerMode, SessionId};
use std::sync::Arc;

/// Maximum 0-RTT early-data plaintext, in bytes (wire V3, Phase 4.1).
/// The client constructor rejects a larger payload; the server drops
/// an oversized blob and continues as a normal 1-RTT handshake. Caps
/// the work an unauthenticated peer can force before the handshake
/// completes.
pub const EARLY_DATA_MAX_LEN: usize = 16 * 1024;

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

/// V3 ClientHello — carries 0-RTT early-data alongside the base
/// V1/V2 fields (wire V3, Phase 4.1).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ClientHelloV3 {
    /// The V1/V2 `ClientHello` fields. `base.version` is `3` for a V3
    /// envelope, and `base.resume_session_id` carries the ticket id
    /// the early-data is keyed against.
    pub base: ClientHello,
    /// AEAD-sealed early-data blob — AES-256-GCM under a key both
    /// peers derive from the prior session's `resumption_secret` via
    /// `crypto::kdf::derive_early_data_keying`. `None` means a V3
    /// client that isn't sending 0-RTT data on this connect.
    pub early_data: Option<Vec<u8>>,
}

/// Server response to ClientHello
#[derive(Debug)]
pub enum HandshakeResponse {
    /// Success: Continue with ServerHello and Session
    Success(ServerHello, Session),
    /// V3 success: `ServerHelloV3` + `Session` + the decrypted 0-RTT
    /// early-data plaintext (`None` when the client sent no early-data
    /// or it was rejected — `ServerHelloV3.early_data_accepted`
    /// carries the verdict the client sees).
    SuccessV3(ServerHelloV3, Session, Option<Vec<u8>>),
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

/// V3 ServerHello — the base `ServerHello` plus the 0-RTT verdict.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ServerHelloV3 {
    /// The base `ServerHello` fields.
    pub base: ServerHello,
    /// `true` iff the server decrypted and accepted the client's
    /// early-data. `false` when there was none, the resumption
    /// ticket was unknown/expired, the blob exceeded the size cap,
    /// or AEAD decryption failed — in every `false` case the
    /// handshake still completes as a normal 1-RTT exchange.
    pub early_data_accepted: bool,
}

// ── Version-prefixed handshake envelopes (wire V3, Phase 4.1) ────────────
//
// Every handshake message now travels inside a borsh enum. Borsh writes a
// 1-byte discriminant ahead of the body, so a receiver dispatches off that
// prefix instead of guessing the struct shape. From this point every wire
// bump adds an enum arm and stays cleanly forward-decodable.
//
// Introducing the envelope is a one-time pre-1.0 wire break for *every*
// version (the discriminant byte shifts the layout) — accepted on the same
// footing as the `ml-kem` primitive swap. See `docs/protocol/PROTOCOL.md`
// §12.

/// Versioned wire envelope for the `ClientHello` message. The `V12` arm
/// carries the V1/V2 `ClientHello` (its inner `version` byte distinguishes
/// 1 vs 2). The `V3` arm carries `ClientHelloV3` for 0-RTT early-data.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum ClientHelloEnvelope {
    /// V1 / V2 `ClientHello`.
    V12(ClientHello),
    /// V3 `ClientHello` with optional 0-RTT early-data.
    V3(ClientHelloV3),
}

/// Versioned wire envelope for the `ServerHello` message. The `Unsupported`
/// arm is a transcript-free, pre-session reply telling a client "I do not
/// speak the envelope variant you sent" — the client then falls back to V2.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum ServerHelloEnvelope {
    /// V1 / V2 `ServerHello`.
    V12(ServerHello),
    /// V3 `ServerHello` with the 0-RTT accept/reject verdict.
    V3(ServerHelloV3),
    /// The server does not speak the envelope variant the client sent
    /// (e.g. a V12-only handshake path received a V3 ClientHello).
    /// Transcript-free and pre-session — the client falls back to a
    /// plain V2 handshake on receipt.
    Unsupported,
}

/// Versioned wire envelope for the `HelloRetryRequest` message. Retry
/// carries no version-specific data; the envelope exists only so every
/// handshake frame shares the uniform 1-byte prefix.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum HelloRetryRequestEnvelope {
    /// V1 / V2 `HelloRetryRequest`.
    V12(HelloRetryRequest),
}

/// Handshake transcript for signing (V1 / V2 path).
#[derive(BorshSerialize)]
struct HandshakeTranscript<'a> {
    client_hello: &'a ClientHello,
    server_key_package: &'a HybridKeyPackage,
    ciphertext: &'a HybridCiphertext,
    server_verify_key: &'a HybridVerifyingKey,
    session_id: &'a [u8; 32],
}

/// Handshake transcript for signing (V3 path). Identical to
/// [`HandshakeTranscript`] except it embeds the full `ClientHelloV3`,
/// so the signature covers the early-data ciphertext too — a tampered
/// or stripped early-data blob breaks the client-side signature check.
#[derive(BorshSerialize)]
struct HandshakeTranscriptV3<'a> {
    client_hello: &'a ClientHelloV3,
    server_key_package: &'a HybridKeyPackage,
    ciphertext: &'a HybridCiphertext,
    server_verify_key: &'a HybridVerifyingKey,
    session_id: &'a [u8; 32],
}

/// Hash a borsh-serializable transcript. Generic over the transcript
/// type so the V1/V2 and V3 paths share one implementation; the V12
/// transcript bytes are byte-identical to pre-V3 builds (same struct,
/// same borsh layout).
fn compute_transcript_hash<T: BorshSerialize>(transcript: &T) -> Result<[u8; 32], HandshakeError> {
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
    /// Server-side resumption cache (Phase 4.1). Stores
    /// `ResumptionTicket` keyed on the session id derived at handshake
    /// success. Bounded LRU with a 1-hour ticket lifetime by default;
    /// `try_resume` returns a forward-secret derived secret per call.
    /// `Arc<Mutex<>>` so all handshake threads share one cache.
    #[zeroize(skip)]
    session_cache: Arc<parking_lot::Mutex<SessionCache>>,
}

impl HandshakeServer {
    pub fn new() -> Result<Self, HandshakeError> {
        let (signing_key, _verifying_key) = HybridSigningKey::generate();
        Self::with_signing_key(signing_key)
    }

    /// Build a `HandshakeServer` from a caller-supplied long-lived
    /// [`HybridSigningKey`] (Phase 7.4 follow-up).
    ///
    /// Used by embedders that persist the server's signing key across
    /// restarts so client pinning material does not change on every
    /// boot. The verifying key is derived from the supplied signing key,
    /// the per-process master secret is freshly generated, and the
    /// remaining state (PoW counters, session cache) initializes the
    /// same way as [`Self::new`].
    ///
    /// The supplied `signing_key` is moved in and held under
    /// `HandshakeServer`'s [`ZeroizeOnDrop`] — the same memory-hygiene
    /// invariant as the auto-generated path.
    pub fn with_signing_key(signing_key: HybridSigningKey) -> Result<Self, HandshakeError> {
        let verifying_key = signing_key.verifying_key();

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
            session_cache: Arc::new(parking_lot::Mutex::new(SessionCache::new())),
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

        // Phase 4.1 — 0-RTT resumption fast path (V12 path).
        //
        // If the client offered a `resume_session_id` AND the server's
        // cache holds a still-valid ticket for it, treat the client as
        // already-vetted: skip the cookie/PoW DoS gate. This is safe
        // because the resume_session_id is bound to a per-(server,
        // client) shared secret from a past handshake — only the
        // legitimate prior client could hold it.
        //
        // `try_resume` is **one-shot**: it consumes the ticket here. A
        // V12 resume therefore burns the resume credit for the
        // cookie/PoW bypass; on handshake success a fresh ticket is
        // minted below, so the credit "rolls over". A replayed
        // ClientHello finds no ticket and falls back to the normal
        // cookie/PoW gate. The KEM round-trip still runs, so forward
        // secrecy is preserved by the fresh X25519+ML-KEM secret.
        //
        // The V3 path (`process_client_hello_v3`) additionally uses the
        // returned secret to decrypt early-data — see that method.
        let cookie_pow_bypass = if let Some(rid) = client_hello.resume_session_id {
            self.session_cache.lock().try_resume(&rid).is_some()
        } else {
            false
        };

        // 2. Stateless Checks (Cookie & PoW) — shared with the V3 path.
        if let Err(resp) =
            self.cookie_pow_gate(client_hello, difficulty, client_ip, cookie_pow_bypass)
        {
            return resp;
        }

        // 3. Hybrid Key Exchange
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
        let (_ephemeral_kem_secret, ephemeral_kem_public) = HybridSecretKey::generate();

        // 4. Session Derivation
        let session_id_bytes = derive_session_id(&shared_secret, &client_hello.nonce);
        let session_id = SessionId::from_bytes(session_id_bytes);

        // 5. Sign Transcript
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

        // 6. Build + wire the Session, derive the resumption secret,
        // stash a ticket — shared with the V3 path. V1/V2 packets ride
        // the version the client offered.
        let session = match self.finalize_session(
            &shared_secret,
            session_id,
            session_id_bytes,
            client_hello.version,
        ) {
            Ok(s) => s,
            Err(resp) => return resp,
        };

        HandshakeResponse::Success(server_hello, session)
    }

    /// V3 handshake — same flow as [`process_client_hello`] plus 0-RTT
    /// early-data: a resuming client may carry an AEAD-sealed payload
    /// inside `ClientHelloV3`, which the server decrypts here using a
    /// key derived from the prior session's `resumption_secret`.
    ///
    /// Early-data is **best-effort**: an unknown/expired ticket, an
    /// oversized blob, or an AEAD failure all leave `early_data` as
    /// `None` and `early_data_accepted` as `false` — the handshake
    /// still completes as a normal 1-RTT exchange. Forward secrecy of
    /// the post-handshake session is preserved by the fresh hybrid KEM
    /// regardless.
    #[tracing::instrument(
        name = "phantom.handshake.process_client_hello_v3",
        skip_all,
        fields(
            client_ip = %client_ip,
            difficulty = difficulty,
            has_early_data = ch3.early_data.is_some(),
        ),
    )]
    pub fn process_client_hello_v3(
        &self,
        ch3: &ClientHelloV3,
        difficulty: u8,
        client_ip: IpAddr,
    ) -> HandshakeResponse {
        self.record_handshake();
        let client_hello = &ch3.base;

        // The V3 envelope already routed us here; the inner version
        // byte must agree (defense-in-depth — it is transcript-bound).
        if client_hello.version != 3 {
            return HandshakeResponse::Fail(HandshakeError::UnsupportedVersion);
        }

        // Resume fast-path. Unlike the V12 path we keep the raw
        // `resumption_secret` (and the `resume_session_id`) so we can
        // derive the early-data key. `try_resume` is one-shot — the
        // ticket is consumed here.
        let resumed: Option<([u8; 32], [u8; 32])> =
            if let Some(rid) = client_hello.resume_session_id {
                self.session_cache
                    .lock()
                    .try_resume(&rid)
                    .map(|(secret, _suite)| (rid, secret))
            } else {
                None
            };
        let cookie_pow_bypass = resumed.is_some();

        if let Err(resp) =
            self.cookie_pow_gate(client_hello, difficulty, client_ip, cookie_pow_bypass)
        {
            return resp;
        }

        // Best-effort early-data decryption. Only attempted when the
        // client both offered a blob AND presented a valid ticket.
        let early_data_plaintext: Option<Vec<u8>> = match (&resumed, &ch3.early_data) {
            (Some((rid, resumption_secret)), Some(blob)) => {
                decrypt_early_data(resumption_secret, &client_hello.nonce, rid, blob)
            }
            _ => None,
        };
        let early_data_accepted = early_data_plaintext.is_some();

        // Hybrid Key Exchange (PFS preserved — a fresh KEM secret even
        // on the 0-RTT path).
        let (shared_secret, ciphertext) = match client_hello.client_key_package.encapsulate() {
            Ok(res) => res,
            Err(e) => return HandshakeResponse::Fail(HandshakeError::KemFailed(e.to_string())),
        };
        let (_ephemeral_kem_secret, ephemeral_kem_public) = HybridSecretKey::generate();

        let session_id_bytes = derive_session_id(&shared_secret, &client_hello.nonce);
        let session_id = SessionId::from_bytes(session_id_bytes);

        // V3 transcript — covers the WHOLE `ClientHelloV3`, including the
        // early-data ciphertext, so a tampered or stripped blob breaks
        // the client-side signature check.
        let transcript = HandshakeTranscriptV3 {
            client_hello: ch3,
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

        let base = ServerHello {
            server_key_package: ephemeral_kem_public,
            ciphertext,
            server_verify_key: self.verifying_key.clone(),
            signature,
            session_id: session_id_bytes,
        };

        // V3 handshake → V2 packet format: early-data is consumed at
        // handshake time, so no new packet header is needed and the
        // data pump routes V2 packets as usual.
        let session = match self.finalize_session(&shared_secret, session_id, session_id_bytes, 2) {
            Ok(s) => s,
            Err(resp) => return resp,
        };

        let server_hello_v3 = ServerHelloV3 {
            base,
            early_data_accepted,
        };
        HandshakeResponse::SuccessV3(server_hello_v3, session, early_data_plaintext)
    }

    /// The cookie / Proof-of-Work DoS gate. Returns `Err(response)` —
    /// a ready-to-send `Retry` or `Fail` — when the client must not
    /// yet proceed; `Ok(())` when it has cleared the gate (or `bypass`
    /// was set by a valid one-shot resumption ticket). Shared by the
    /// V12 and V3 server paths.
    // `HandshakeResponse` is intentionally large — boxing it would add a
    // heap allocation on every call, penalising the hot non-error path.
    // The type is internal and lives only on the handshake stack, so the
    // size is acceptable.
    #[allow(clippy::result_large_err)]
    fn cookie_pow_gate(
        &self,
        client_hello: &ClientHello,
        difficulty: u8,
        client_ip: IpAddr,
        bypass: bool,
    ) -> Result<(), HandshakeResponse> {
        // Cookie freshness (Phase 1.10): `validate_cookie` accepts the current
        // bucket OR the immediately-previous bucket (5-minute buckets, so
        // 5-10 min effective validity). Comparisons are constant-time.
        let cookie_valid = match client_hello.cookie {
            Some(c) => match validate_cookie(&self.master_secret, client_ip, &c) {
                Ok(v) => v,
                Err(e) => return Err(HandshakeResponse::Fail(e)),
            },
            None => false,
        };
        // Pre-compute a fresh cookie to hand to the client on a retry.
        let expected_cookie = match generate_cookie(&self.master_secret, client_ip) {
            Ok(c) => c,
            Err(e) => return Err(HandshakeResponse::Fail(e)),
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
                Err(e) => return Err(HandshakeResponse::Fail(e)),
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
                        Err(e) => return Err(HandshakeResponse::Fail(e)),
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
                    Err(e) => return Err(HandshakeResponse::Fail(e)),
                };
                challenge = Some(PoWChallenge::new_stateless(
                    difficulty,
                    client_ip.to_string().as_bytes(),
                    &derived,
                ));
            }
        }

        if !bypass && (!cookie_valid || !pow_valid) {
            return Err(HandshakeResponse::Retry(HelloRetryRequest {
                challenge,
                cookie: if !cookie_valid {
                    Some(expected_cookie)
                } else {
                    None
                },
            }));
        }
        Ok(())
    }

    /// Build the post-handshake `Session` from the negotiated
    /// `shared_secret`: derive the AEAD `CryptoState`, set the
    /// packet-routing wire version, derive + install the resumption
    /// secret, and stash a resumption ticket in the cache. Shared by
    /// the V12 and V3 server paths.
    ///
    /// `packet_wire_version` is what the data pump uses to pick the V1
    /// vs V2 packet codec — `client_hello.version` for the V12 path,
    /// `2` for the V3 path (V3 is a handshake-only bump; early-data is
    /// consumed at handshake time and the session then routes V2
    /// packets).
    #[allow(clippy::result_large_err)]
    fn finalize_session(
        &self,
        shared_secret: &[u8; 32],
        session_id: SessionId,
        session_id_bytes: [u8; 32],
        packet_wire_version: u8,
    ) -> Result<Session, HandshakeResponse> {
        let crypto = CryptoState::new(shared_secret, true)
            .map_err(|e| HandshakeResponse::Fail(HandshakeError::KemFailed(e.to_string())))?;

        // is_server=true and traffic_secret=shared_secret seed the rekey
        // chain (Phase 1.5) so the server can later derive forward.
        let session = Session::from_derived(
            session_id,
            crypto,
            SchedulerMode::LowLatency,
            *shared_secret,
            true,
        );
        session.set_wire_version(packet_wire_version);

        // Derive resumption secret and stash a one-shot ticket so a
        // future ClientHello carrying this session id can skip
        // cookie/PoW and (on the V3 path) carry 0-RTT early-data.
        let mut resumption_secret = [0u8; 32];
        let hk = hkdf::Hkdf::<Sha256>::new(None, shared_secret);
        if hk
            .expand(b"phantom-resumption-secret-v1", &mut resumption_secret)
            .is_ok()
        {
            session.set_resumption_secret(resumption_secret);
            self.session_cache.lock().store(
                session_id_bytes,
                &resumption_secret,
                CipherSuite::Aes256Gcm,
            );
        }
        Ok(session)
    }

    pub fn verifying_key(&self) -> &HybridVerifyingKey {
        &self.verifying_key
    }

    /// Number of tickets currently held in the resumption cache.
    /// Exposed for metrics / tests; not on the hot path. Phase 4.1.
    pub fn session_cache_len(&self) -> usize {
        self.session_cache.lock().len()
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

    /// Build a `ClientHello` carrying a `resume_session_id`. The
    /// server will check its session cache; if the id is known and
    /// the ticket is still valid, cookie/PoW are bypassed (Phase
    /// 4.1). The `resumption_secret` half of the hint is held by the
    /// caller and used for any application-layer 0-RTT data.
    pub fn create_client_hello_with_resume(
        &self,
        version: u8,
        resume_session_id: [u8; 32],
    ) -> ClientHello {
        ClientHello {
            client_key_package: self.kem_public.clone(),
            client_verify_key: self.verifying_key.clone(),
            nonce: self.nonce,
            version,
            cookie: None,
            pow_solution: None,
            resume_session_id: Some(resume_session_id),
        }
    }

    /// Build a **V3** `ClientHello` carrying optional 0-RTT early-data
    /// (wire V3, Phase 4.1).
    ///
    /// `resume_session_id` and `resumption_secret` are the two halves
    /// of a prior session's `Session::resumption_hint()`. When
    /// `early_data` is `Some`, it is sealed (AES-256-GCM) under a key
    /// derived from `(resumption_secret, self.nonce)` and embedded in
    /// the returned `ClientHelloV3`; the server decrypts it with the
    /// matching key.
    ///
    /// The caller MUST ensure `early_data.len() <= EARLY_DATA_MAX_LEN`
    /// — `PhantomSession::connect_with_resumption` enforces this and
    /// returns an error for oversized payloads.
    pub fn create_client_hello_v3(
        &self,
        resume_session_id: [u8; 32],
        resumption_secret: &[u8; 32],
        early_data: Option<&[u8]>,
    ) -> ClientHelloV3 {
        let base = ClientHello {
            client_key_package: self.kem_public.clone(),
            client_verify_key: self.verifying_key.clone(),
            nonce: self.nonce,
            version: 3,
            cookie: None,
            pow_solution: None,
            resume_session_id: Some(resume_session_id),
        };
        let sealed = early_data
            .and_then(|pt| seal_early_data(resumption_secret, &self.nonce, &resume_session_id, pt));
        ClientHelloV3 {
            base,
            early_data: sealed,
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

    /// V3 counterpart of [`process_server_hello`] (wire V3, Phase 4.1).
    ///
    /// Verifies the server's signature over the V3 transcript (which
    /// covers the whole `ClientHelloV3`, early-data included) and
    /// returns the established `Session` together with the server's
    /// 0-RTT verdict — `ServerHelloV3.early_data_accepted`. A `false`
    /// verdict means the server did not consume the early-data; the
    /// caller must re-send that payload over the normal channel.
    #[tracing::instrument(
        name = "phantom.handshake.process_server_hello_v3",
        skip_all,
        fields(pinned = expected_server_key.is_some()),
    )]
    pub fn process_server_hello_v3(
        &self,
        client_hello: &ClientHelloV3,
        server_hello: &ServerHelloV3,
        expected_server_key: Option<&HybridVerifyingKey>,
    ) -> Result<(Session, bool), HandshakeError> {
        let base = &server_hello.base;

        // 1. Verify Identity
        if let Some(expected) = expected_server_key {
            if expected != &base.server_verify_key {
                return Err(HandshakeError::ServerIdentityMismatch);
            }
        }

        // 2. Verify Signature over the V3 transcript.
        let transcript = HandshakeTranscriptV3 {
            client_hello,
            server_key_package: &base.server_key_package,
            ciphertext: &base.ciphertext,
            server_verify_key: &base.server_verify_key,
            session_id: &base.session_id,
        };
        let transcript_hash = compute_transcript_hash(&transcript)?;
        base.server_verify_key
            .verify(&transcript_hash, &base.signature)
            .map_err(|e| HandshakeError::KemFailed(format!("Signature check failed: {:?}", e)))?;

        // 3. Decapsulate
        let shared_secret = self
            .kem_secret
            .decapsulate(&base.ciphertext)
            .map_err(|e| HandshakeError::KemFailed(e.to_string()))?;

        // 4. Create Session
        let session_id = SessionId::from_bytes(base.session_id);
        let crypto = CryptoState::new(&shared_secret, false)
            .map_err(|e| HandshakeError::KemFailed(e.to_string()))?;
        let session = Session::from_derived(
            session_id,
            crypto,
            SchedulerMode::LowLatency,
            shared_secret,
            false,
        );
        // V3 is a handshake-only bump — the session routes V2 packets,
        // matching the server's `finalize_session(.., 2)`.
        session.set_wire_version(2);

        // 5. Derive resumption secret (seeds the NEXT 0-RTT).
        let mut resumption_secret = [0u8; 32];
        let hk = hkdf::Hkdf::<Sha256>::new(None, &shared_secret);
        if hk
            .expand(b"phantom-resumption-secret-v1", &mut resumption_secret)
            .is_ok()
        {
            session.set_resumption_secret(resumption_secret);
        }

        *self.stage.write() = HandshakeStage::Established;
        Ok((session, server_hello.early_data_accepted))
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

/// Best-effort decryption of a V3 early-data blob (wire V3, Phase 4.1).
///
/// Both peers derive the AEAD `(key, nonce)` from the prior session's
/// `resumption_secret` and *this* connect's `client_nonce` via
/// [`derive_early_data_keying`]. AAD binds the blob to its context:
/// `resume_session_id || client_nonce`.
///
/// Returns `None` — early-data rejected, the handshake simply
/// continues as 1-RTT — when:
/// - the sealed blob exceeds the [`EARLY_DATA_MAX_LEN`] cap (checked
///   before any crypto work — anti-DoS), or
/// - the AEAD tag fails to verify (tampered / wrong key).
fn decrypt_early_data(
    resumption_secret: &[u8; 32],
    client_nonce: &[u8; 32],
    resume_session_id: &[u8; 32],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    // A sealed blob is `plaintext || 16-byte GCM tag`. Reject anything
    // whose plaintext would exceed the cap before doing crypto work.
    if sealed.len() > EARLY_DATA_MAX_LEN + 16 {
        return None;
    }
    let (key, nonce) = derive_early_data_keying(resumption_secret, client_nonce);
    // Server is the responder for the one-directional early-data
    // channel: `with_suite_peer` swaps send/recv so its `recv_key`
    // matches the client's `send_key`.
    let aead = CryptoSession::with_suite_peer(&key, CipherSuite::Aes256Gcm).ok()?;
    let mut aad = [0u8; 64];
    aad[..32].copy_from_slice(resume_session_id);
    aad[32..].copy_from_slice(client_nonce);
    aead.decrypt_with_nonce(nonce, &aad, sealed).ok()
}

/// Seal a V3 early-data plaintext for transport inside a
/// `ClientHelloV3` (wire V3, Phase 4.1). Mirror of
/// [`decrypt_early_data`].
///
/// The client is the *initiator* of the one-directional early-data
/// channel — `with_suite` (no key swap) so its `send_key` matches the
/// server's `recv_key`. AAD is `resume_session_id || client_nonce`,
/// identical to the server side.
///
/// Returns `None` only on the structurally-improbable AEAD-key-init
/// failure; the caller treats that as "no early-data" and the
/// handshake proceeds 1-RTT.
fn seal_early_data(
    resumption_secret: &[u8; 32],
    client_nonce: &[u8; 32],
    resume_session_id: &[u8; 32],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let (key, nonce) = derive_early_data_keying(resumption_secret, client_nonce);
    let aead = CryptoSession::with_suite(&key, CipherSuite::Aes256Gcm).ok()?;
    let mut aad = [0u8; 64];
    aad[..32].copy_from_slice(resume_session_id);
    aad[32..].copy_from_slice(client_nonce);
    aead.encrypt_with_nonce(nonce, &aad, plaintext).ok()
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

    /// Phase 4.1 — after a successful handshake, the server caches a
    /// ticket keyed on the negotiated session id, and the resulting
    /// `Session` exposes a `resumption_hint` so the client can store
    /// it for a future connect.
    #[tokio::test]
    async fn first_handshake_caches_ticket_and_exposes_hint() {
        let server = HandshakeServer::new().expect("HandshakeServer::new");
        let client = HandshakeClient::new().expect("HandshakeClient::new");
        let client_ip = "127.0.0.1".parse().unwrap();

        let hello = client.create_client_hello();
        let cookie = match server.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(r) => r.cookie.unwrap(),
            _ => panic!("expected retry"),
        };
        let mut hello_retry = hello.clone();
        hello_retry.cookie = Some(cookie);
        let (server_hello, server_session) =
            match server.process_client_hello(&hello_retry, 0, client_ip) {
                HandshakeResponse::Success(h, s) => (h, s),
                _ => panic!("expected success"),
            };
        let client_session = client
            .process_server_hello(&hello_retry, &server_hello, Some(server.verifying_key()))
            .unwrap();

        // Server now has exactly one ticket.
        assert_eq!(server.session_cache_len(), 1);
        // Both sides expose a `resumption_hint`. The session id and
        // resumption secret match between client and server.
        let s_hint = server_session.resumption_hint().expect("server hint");
        let c_hint = client_session.resumption_hint().expect("client hint");
        assert_eq!(s_hint.0, c_hint.0, "session id matches across sides");
        assert_eq!(s_hint.1, c_hint.1, "resumption secret matches");
    }

    /// Phase 4.1 — a ClientHello carrying a cached `resume_session_id`
    /// bypasses the cookie/PoW DoS gate (it goes straight to success
    /// on the first call, with no Retry). The full KEM still runs so
    /// PFS is preserved.
    #[tokio::test]
    async fn cached_resume_session_id_skips_cookie_and_pow() {
        let server = HandshakeServer::new().expect("HandshakeServer::new");
        let client_ip = "127.0.0.1".parse().unwrap();

        // Drive a full handshake to populate the cache.
        let first_client = HandshakeClient::new().unwrap();
        let first_hello = first_client.create_client_hello();
        let cookie = match server.process_client_hello(&first_hello, 0, client_ip) {
            HandshakeResponse::Retry(r) => r.cookie.unwrap(),
            _ => panic!("expected retry"),
        };
        let mut hello_retry = first_hello.clone();
        hello_retry.cookie = Some(cookie);
        let (_first_server_hello, first_server_session) =
            match server.process_client_hello(&hello_retry, 0, client_ip) {
                HandshakeResponse::Success(h, s) => (h, s),
                _ => panic!("expected success"),
            };
        let (resume_id, _resume_secret) = first_server_session.resumption_hint().unwrap();

        // Second client offers the resume_session_id WITHOUT a cookie.
        // Server should accept immediately (no Retry).
        let second_client = HandshakeClient::new().unwrap();
        let resume_hello = second_client.create_client_hello_with_resume(2, resume_id);
        match server.process_client_hello(&resume_hello, 0, client_ip) {
            HandshakeResponse::Success(_, _) => {} // expected
            HandshakeResponse::Retry(_) => {
                panic!("resume_session_id should bypass cookie/PoW gate")
            }
            HandshakeResponse::SuccessV3(..) => {
                panic!("V12 process_client_hello must not return SuccessV3")
            }
            HandshakeResponse::Fail(e) => panic!("unexpected failure: {:?}", e),
        }
    }

    /// Phase 4.1 — unknown `resume_session_id` does NOT bypass cookie.
    /// The server simply ignores the unknown id and falls through to
    /// the normal cookie/PoW path.
    #[tokio::test]
    async fn unknown_resume_session_id_does_not_bypass_cookie() {
        let server = HandshakeServer::new().unwrap();
        let client = HandshakeClient::new().unwrap();
        let client_ip = "127.0.0.1".parse().unwrap();

        // An id the server has never seen.
        let bogus_id = [0xFFu8; 32];
        let hello = client.create_client_hello_with_resume(2, bogus_id);
        match server.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(_) => {} // expected — normal cookie flow
            other => panic!(
                "expected Retry for unknown resume id, got {:?}",
                matches!(other, HandshakeResponse::Success(..)),
            ),
        }
    }

    // ── Wire V3 / 0-RTT early-data (Phase 4.1) ──

    /// Drive a full V12 handshake and return the resumption hint the
    /// server minted for it — the `(session_id, resumption_secret)`
    /// a V3 client needs.
    fn first_handshake_for_hint(
        server: &HandshakeServer,
        client_ip: std::net::IpAddr,
    ) -> ([u8; 32], [u8; 32]) {
        let client = HandshakeClient::new().unwrap();
        let hello = client.create_client_hello();
        let cookie = match server.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(r) => r.cookie.unwrap(),
            _ => panic!("expected retry"),
        };
        let mut retry = hello.clone();
        retry.cookie = Some(cookie);
        match server.process_client_hello(&retry, 0, client_ip) {
            HandshakeResponse::Success(_, session) => session.resumption_hint().unwrap(),
            _ => panic!("expected success"),
        }
    }

    #[test]
    fn envelope_roundtrip_v12_and_v3() {
        let client = HandshakeClient::new().unwrap();

        // ClientHelloEnvelope::V12 round-trips.
        let v12 = ClientHelloEnvelope::V12(client.create_client_hello());
        let bytes = borsh::to_vec(&v12).unwrap();
        assert!(matches!(
            borsh::from_slice::<ClientHelloEnvelope>(&bytes).unwrap(),
            ClientHelloEnvelope::V12(_)
        ));

        // ClientHelloEnvelope::V3 round-trips, early-data preserved.
        let v3 = ClientHelloEnvelope::V3(client.create_client_hello_v3(
            [7u8; 32],
            &[9u8; 32],
            Some(b"early"),
        ));
        let bytes = borsh::to_vec(&v3).unwrap();
        match borsh::from_slice::<ClientHelloEnvelope>(&bytes).unwrap() {
            ClientHelloEnvelope::V3(ch3) => {
                assert_eq!(ch3.base.version, 3);
                assert!(ch3.early_data.is_some(), "sealed blob preserved");
            }
            ClientHelloEnvelope::V12(_) => panic!("expected V3"),
        }

        // ServerHelloEnvelope::Unsupported is a 1-byte wire token.
        let bytes = borsh::to_vec(&ServerHelloEnvelope::Unsupported).unwrap();
        assert!(matches!(
            borsh::from_slice::<ServerHelloEnvelope>(&bytes).unwrap(),
            ServerHelloEnvelope::Unsupported
        ));
    }

    #[test]
    fn unknown_envelope_discriminant_errors_not_panics() {
        // `ClientHelloEnvelope` has discriminants 0 (V12) and 1 (V3).
        // An out-of-range discriminant must produce a clean `Err`, not
        // a panic — this is what makes future version bumps decode
        // cleanly off the 1-byte prefix.
        let bogus = [99u8, 0, 0, 0, 0, 0, 0, 0];
        assert!(borsh::from_slice::<ClientHelloEnvelope>(&bogus).is_err());
        assert!(borsh::from_slice::<ServerHelloEnvelope>(&bogus).is_err());
    }

    #[tokio::test]
    async fn v3_early_data_round_trip() {
        let server = HandshakeServer::new().unwrap();
        let client_ip = "127.0.0.1".parse().unwrap();
        let (resume_id, resume_secret) = first_handshake_for_hint(&server, client_ip);

        // Second connect: V3 with a 0-RTT early-data payload.
        let client = HandshakeClient::new().unwrap();
        let early_payload = b"zero-rtt application bytes";
        let ch3 = client.create_client_hello_v3(resume_id, &resume_secret, Some(early_payload));

        match server.process_client_hello_v3(&ch3, 0, client_ip) {
            HandshakeResponse::SuccessV3(sh3, _session, early_data) => {
                assert!(sh3.early_data_accepted, "server accepted the early-data");
                assert_eq!(
                    early_data.as_deref(),
                    Some(&early_payload[..]),
                    "server decrypted the exact payload the client sealed"
                );
                // The client verifies the V3 ServerHello and learns the
                // same verdict.
                let (_session, accepted) = client
                    .process_server_hello_v3(&ch3, &sh3, Some(server.verifying_key()))
                    .expect("client verifies the V3 ServerHello");
                assert!(accepted, "client sees early_data_accepted == true");
            }
            other => panic!(
                "expected SuccessV3, got {}",
                match other {
                    HandshakeResponse::Retry(_) => "Retry",
                    HandshakeResponse::Success(..) => "Success",
                    HandshakeResponse::Fail(_) => "Fail",
                    HandshakeResponse::SuccessV3(..) => unreachable!(),
                }
            ),
        }
    }

    #[tokio::test]
    async fn v3_oversized_early_data_rejected_but_handshake_succeeds() {
        let server = HandshakeServer::new().unwrap();
        let client_ip = "127.0.0.1".parse().unwrap();
        let (resume_id, resume_secret) = first_handshake_for_hint(&server, client_ip);

        // A blob whose sealed length exceeds EARLY_DATA_MAX_LEN + tag.
        let huge = vec![0u8; EARLY_DATA_MAX_LEN + 1];
        let client = HandshakeClient::new().unwrap();
        let ch3 = client.create_client_hello_v3(resume_id, &resume_secret, Some(&huge));

        match server.process_client_hello_v3(&ch3, 0, client_ip) {
            HandshakeResponse::SuccessV3(sh3, _session, early_data) => {
                assert!(!sh3.early_data_accepted, "oversized blob rejected");
                assert!(early_data.is_none(), "no plaintext surfaces");
            }
            _ => panic!("handshake must still succeed as 1-RTT"),
        }
    }

    #[tokio::test]
    async fn v3_corrupted_early_data_rejected_but_handshake_succeeds() {
        let server = HandshakeServer::new().unwrap();
        let client_ip = "127.0.0.1".parse().unwrap();
        let (resume_id, resume_secret) = first_handshake_for_hint(&server, client_ip);

        // Build a V3 ClientHello, then replace the sealed blob with
        // in-range garbage — AEAD verification must fail.
        let client = HandshakeClient::new().unwrap();
        let mut ch3 = client.create_client_hello_v3(resume_id, &resume_secret, None);
        ch3.early_data = Some(vec![0xFFu8; 128]);

        match server.process_client_hello_v3(&ch3, 0, client_ip) {
            HandshakeResponse::SuccessV3(sh3, _session, early_data) => {
                assert!(!sh3.early_data_accepted, "AEAD failure → rejected");
                assert!(early_data.is_none());
            }
            _ => panic!("handshake must still succeed as 1-RTT"),
        }
    }

    #[tokio::test]
    async fn v3_unknown_ticket_falls_back_to_cookie_retry() {
        // A V3 ClientHello whose resume_session_id the server has never
        // seen gets no cookie/PoW bypass — and with no cookie attached,
        // the server demands one via Retry.
        let server = HandshakeServer::new().unwrap();
        let client_ip = "127.0.0.1".parse().unwrap();
        let client = HandshakeClient::new().unwrap();
        let ch3 = client.create_client_hello_v3([0xAB; 32], &[0xCD; 32], Some(b"hi"));
        assert!(
            matches!(
                server.process_client_hello_v3(&ch3, 0, client_ip),
                HandshakeResponse::Retry(_)
            ),
            "unknown ticket → no bypass → cookie Retry"
        );
    }
}
