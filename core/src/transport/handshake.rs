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

/// Maximum 0-RTT early-data plaintext, in bytes.
/// The client constructor rejects a larger payload; the server drops
/// an oversized blob and continues as a normal 1-RTT handshake. Caps
/// the work an unauthenticated peer can force before the handshake
/// completes.
pub const EARLY_DATA_MAX_LEN: usize = 16 * 1024;

/// Handshake processing stages
/// Compile-time protocol-variant tag, baked into every `ClientHello`
/// (cleartext field) **and** the signed handshake transcript. Peers
/// reject mismatched variants up front with
/// [`HandshakeError::ProtocolVariantMismatch`]; even an attacker who
/// rewrites the cleartext field cannot escape detection because the
/// transcript signature is computed over the build's own variant.
///
/// The `--features fips` build advertises `phantom-fips-1` so a
/// fips client and a non-fips server (or vice versa) fail loudly at
/// handshake time rather than producing a silently-wrong shared
/// secret across mismatched primitive sets.
#[cfg(not(feature = "fips"))]
pub const PROTOCOL_VARIANT: &[u8] = b"phantom-default-1";
#[cfg(feature = "fips")]
pub const PROTOCOL_VARIANT: &[u8] = b"phantom-fips-1";

/// The sole protocol version carried in `ClientHello.version` and bound into the
/// handshake transcript. Pinned to one value — the protocol is not negotiated
/// (pre-1.0, no users). It is a tamper-check anchor and a hook for a future,
/// deliberate version increment.
pub const PROTOCOL_VERSION: u8 = 1;

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

/// Client hello message (initiates handshake).
///
/// Carries the client's hybrid key material, the pinned [`PROTOCOL_VERSION`]
/// (transcript-bound), the DoS-gate fields (cookie / PoW), an optional
/// resumption id, the build-side [`PROTOCOL_VARIANT`] tag, and an optional
/// AEAD-sealed 0-RTT `early_data` blob.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ClientHello {
    /// hybrid public key for key exchange
    pub client_key_package: HybridKeyPackage,
    /// hybrid verifying key for signatures
    pub client_verify_key: HybridVerifyingKey,
    /// Random nonce (32 bytes) for replay protection
    pub nonce: [u8; 32],
    /// Protocol version. Pinned to [`PROTOCOL_VERSION`] and bound into the
    /// signed handshake transcript; the server rejects any other value with
    /// [`HandshakeError::UnsupportedVersion`].
    pub version: u8,
    /// Stateless generic cookie to prove IP ownership
    pub cookie: Option<[u8; 32]>,
    /// Proof-of-Work solution (if required by server)
    pub pow_solution: Option<PoWSolution>,
    /// Optional session ID for 0-RTT resumption
    pub resume_session_id: Option<[u8; 32]>,
    /// Cleartext copy of [`PROTOCOL_VARIANT`]. Lets the server reject
    /// a mismatched-mode client up front (before signature
    /// verification); the same value is bound into the handshake
    /// transcript so an attacker rewriting this field on the wire is
    /// still caught by the signature check.
    pub protocol_variant: Vec<u8>,
    /// Optional AEAD-sealed 0-RTT early-data — AES-256-GCM under a key both
    /// peers derive from the prior session's `resumption_secret` via
    /// [`derive_early_data_keying`]. `None` means no 0-RTT data on this
    /// connect. The whole `ClientHello` (this field included) is covered by
    /// the transcript signature, so a tampered or stripped blob breaks the
    /// server's signature check (Invariant 7).
    pub early_data: Option<Vec<u8>>,
}

/// Server response to ClientHello
//
// Intentionally large — the `Success` variant carries a full `Session`.
// Boxing it would add a heap allocation on every successful handshake
// (the hot path); the type is internal and lives only on the handshake
// stack, so the size is acceptable. Same rationale as the
// `result_large_err` allow on the gate/finalize helpers below.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum HandshakeResponse {
    /// Success: the `ServerHello` to send back, the established `Session`,
    /// and the decrypted 0-RTT early-data plaintext (`None` when the client
    /// sent none or it was rejected — `ServerHello.early_data_accepted`
    /// carries the verdict the client sees).
    Success(ServerHello, Session, Option<Vec<u8>>),
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
    /// `true` iff the server decrypted and accepted the client's 0-RTT
    /// early-data. `false` when there was none, the resumption ticket was
    /// unknown/expired, the blob exceeded the size cap, or AEAD decryption
    /// failed — in every `false` case the handshake still completes as a
    /// normal 1-RTT exchange.
    pub early_data_accepted: bool,
}

/// Handshake transcript for signing.
///
/// Embeds the whole `ClientHello` by reference — including the optional
/// 0-RTT `early_data` ciphertext — so the server's signature covers it and a
/// tampered or stripped blob breaks the client-side signature check
/// (Invariant 7). The transcript leads with the build-side
/// [`PROTOCOL_VARIANT`] tag, so a cross-mode (fips ↔ non-fips) attempt fails
/// the signature check rather than landing a wrong shared secret. Both peers
/// MUST plumb the same byte string for the signature to verify.
#[derive(BorshSerialize)]
struct HandshakeTranscript<'a> {
    protocol_variant: &'a [u8],
    client_hello: &'a ClientHello,
    server_key_package: &'a HybridKeyPackage,
    ciphertext: &'a HybridCiphertext,
    server_verify_key: &'a HybridVerifyingKey,
    session_id: &'a [u8; 32],
}

/// Hash a borsh-serializable transcript. The transcript leads with the
/// `protocol_variant` tag, so the hash binds the build-side variant.
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
            has_early_data = client_hello.early_data.is_some(),
        ),
    )]
    pub fn process_client_hello(
        &self,
        client_hello: &ClientHello,
        difficulty: u8,
        client_ip: IpAddr,
    ) -> HandshakeResponse {
        // Tally this call before any work is done, so the load counter
        // reflects attempts (including the rejected ones).
        self.record_handshake();

        // Protocol-variant gate. Fail loud (before any KEM / signature work)
        // if the client and server disagree on the build-side
        // `PROTOCOL_VARIANT` tag. The transcript also binds this constant, so
        // an MITM rewrite of the cleartext field is caught on the client's
        // signature check; this explicit field gives operators a clean
        // diagnostic instead of "Signature check failed" (Invariant 10).
        if client_hello.protocol_variant != PROTOCOL_VARIANT {
            return HandshakeResponse::Fail(HandshakeError::ProtocolVariantMismatch {
                expected: PROTOCOL_VARIANT.to_vec(),
                received: client_hello.protocol_variant.clone(),
            });
        }

        // Version pin. The protocol is not negotiated — `version` is a
        // tamper-check anchor pinned to `PROTOCOL_VERSION` and borsh-serialized
        // into the signed transcript, so a network rewrite forces a
        // client-side signature mismatch. Anything else is rejected up front
        // (Invariant 7).
        if client_hello.version != PROTOCOL_VERSION {
            return HandshakeResponse::Fail(HandshakeError::UnsupportedVersion);
        }

        // 0-RTT resumption fast path.
        //
        // If the client offered a `resume_session_id` AND the cache holds a
        // still-valid ticket for it, treat the client as already-vetted: skip
        // the cookie/PoW DoS gate. This is safe because the resume_session_id
        // is bound to a per-(server, client) shared secret from a past
        // handshake — only the legitimate prior client could hold it. We keep
        // the returned `(rid, resumption_secret)` to key best-effort
        // early-data decryption below.
        //
        // `try_resume` is **one-shot**: it consumes the ticket here. On
        // handshake success a fresh ticket is minted, so the credit "rolls
        // over". A replayed ClientHello finds no ticket and falls back to the
        // normal cookie/PoW gate (Invariant 9). The KEM round-trip still runs,
        // so forward secrecy is preserved by the fresh X25519+ML-KEM secret.
        let resumed: Option<([u8; 32], [u8; 32])> =
            client_hello.resume_session_id.and_then(|rid| {
                self.session_cache
                    .lock()
                    .try_resume(&rid)
                    .map(|(secret, _suite)| (rid, secret))
            });
        let cookie_pow_bypass = resumed.is_some();

        // Stateless DoS checks (Cookie & PoW).
        if let Err(resp) =
            self.cookie_pow_gate(client_hello, difficulty, client_ip, cookie_pow_bypass)
        {
            return resp;
        }

        // Best-effort 0-RTT early-data decryption. Only attempted when the
        // client both presented a valid ticket AND carried a sealed blob; any
        // failure (unknown/expired ticket, oversized blob, AEAD failure)
        // leaves `early_data_accepted = false` and completes a normal 1-RTT
        // handshake (Invariant 9). Forward secrecy of the post-handshake
        // session is preserved by the fresh hybrid KEM regardless.
        let early_data_plaintext: Option<Vec<u8>> = match (&resumed, &client_hello.early_data) {
            (Some((rid, resumption_secret)), Some(blob)) => {
                decrypt_early_data(resumption_secret, &client_hello.nonce, rid, blob)
            }
            _ => None,
        };
        let early_data_accepted = early_data_plaintext.is_some();

        // Hybrid Key Exchange (PFS preserved — a fresh KEM secret even on the
        // 0-RTT path).
        let (shared_secret, ciphertext) = match client_hello.client_key_package.encapsulate() {
            Ok(res) => res,
            Err(e) => return HandshakeResponse::Fail(HandshakeError::KemFailed(e.to_string())),
        };

        // Generate a per-session ephemeral hybrid KEM keypair. The public half
        // is bound into the transcript signature (defense-in-depth: commits
        // the server to a session-specific value beyond `session_id` and the
        // client's nonce). The secret half is intentionally discarded — the
        // current protocol does not perform a second KEM round trip using it.
        let (_ephemeral_kem_secret, ephemeral_kem_public) = HybridSecretKey::generate();

        let session_id_bytes = derive_session_id(&shared_secret, &client_hello.nonce);
        let session_id = SessionId::from_bytes(session_id_bytes);

        // Sign the transcript. It embeds the WHOLE `ClientHello` (early-data
        // ciphertext included) plus `PROTOCOL_VARIANT` — a tampered or stripped
        // blob breaks the client-side signature check (Invariants 7, 10).
        let transcript = HandshakeTranscript {
            protocol_variant: PROTOCOL_VARIANT,
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
            early_data_accepted,
        };

        // Build + wire the Session, derive the resumption secret, and stash a
        // fresh one-shot ticket for a future resume / 0-RTT.
        let session = match self.finalize_session(&shared_secret, session_id, session_id_bytes) {
            Ok(s) => s,
            Err(resp) => return resp,
        };

        HandshakeResponse::Success(server_hello, session, early_data_plaintext)
    }

    /// The cookie / Proof-of-Work DoS gate. Returns `Err(response)` —
    /// a ready-to-send `Retry` or `Fail` — when the client must not
    /// yet proceed; `Ok(())` when it has cleared the gate (or `bypass`
    /// was set by a valid one-shot resumption ticket).
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
    /// `shared_secret`: derive the AEAD `CryptoState`, route the packet
    /// codec, derive + install the resumption secret, and stash a
    /// resumption ticket in the cache.
    ///
    /// The protocol version is pinned (`PROTOCOL_VERSION`) and orthogonal to
    /// the on-wire packet codec, which the data pump still selects via
    /// `Session::wire_version()` — set to `2` here until the wire-types
    /// collapse removes the dual codec.
    #[allow(clippy::result_large_err)]
    fn finalize_session(
        &self,
        shared_secret: &[u8; 32],
        session_id: SessionId,
        session_id_bytes: [u8; 32],
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
        session.set_wire_version(2);

        // Derive resumption secret and stash a one-shot ticket so a
        // future ClientHello carrying this session id can skip
        // cookie/PoW and carry 0-RTT early-data.
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

    /// Build the default `ClientHello` — pinned [`PROTOCOL_VERSION`], no
    /// resumption, no 0-RTT early-data. Downgrade resistance comes from the
    /// transcript signature, which binds both `version` and the build-side
    /// [`PROTOCOL_VARIANT`]; a network rewrite of either aborts the handshake
    /// at the client-side signature check.
    pub fn create_client_hello(&self) -> ClientHello {
        ClientHello {
            client_key_package: self.kem_public.clone(),
            client_verify_key: self.verifying_key.clone(),
            nonce: self.nonce,
            version: PROTOCOL_VERSION,
            cookie: None,
            pow_solution: None,
            resume_session_id: None,
            protocol_variant: PROTOCOL_VARIANT.to_vec(),
            early_data: None,
        }
    }

    /// Build a `ClientHello` that resumes a prior session, optionally carrying
    /// 0-RTT `early_data`.
    ///
    /// `resume_session_id` and `resumption_secret` are the two halves of a
    /// prior session's `Session::resumption_hint()`. The server checks its
    /// session cache; a known, still-valid ticket bypasses the cookie/PoW DoS
    /// gate. When `early_data` is `Some`, it is sealed (AES-256-GCM) under a
    /// key derived from `(resumption_secret, self.nonce)` and placed in
    /// `ClientHello.early_data`; the server decrypts it with the matching key
    /// (best-effort — see [`HandshakeServer::process_client_hello`]). The
    /// whole hello, early-data included, is transcript-bound (Invariant 7).
    ///
    /// The caller MUST ensure `early_data.len() <= EARLY_DATA_MAX_LEN`;
    /// `PhantomSession::connect_with_resumption` enforces this and returns an
    /// error for oversized payloads.
    pub fn create_client_hello_with_resume(
        &self,
        resume_session_id: [u8; 32],
        resumption_secret: &[u8; 32],
        early_data: Option<&[u8]>,
    ) -> ClientHello {
        let sealed = early_data
            .and_then(|pt| seal_early_data(resumption_secret, &self.nonce, &resume_session_id, pt));
        ClientHello {
            client_key_package: self.kem_public.clone(),
            client_verify_key: self.verifying_key.clone(),
            nonce: self.nonce,
            version: PROTOCOL_VERSION,
            cookie: None,
            pow_solution: None,
            resume_session_id: Some(resume_session_id),
            protocol_variant: PROTOCOL_VARIANT.to_vec(),
            early_data: sealed,
        }
    }

    /// Verify a `ServerHello` against the `ClientHello` we sent and establish
    /// the client-side `Session`.
    ///
    /// Pinning is mandatory in production — `expected_server_key` is
    /// `Some(&key)` (Invariant 1). The signature is checked over the whole
    /// transcript, which embeds the entire `ClientHello` (early-data
    /// ciphertext included) and the build-side `PROTOCOL_VARIANT` (Invariants
    /// 7, 10). Returns the established `Session` and the 0-RTT verdict:
    /// `Some(true/false)` when the client sent early-data (accepted / rejected
    /// per `server_hello.early_data_accepted`), `None` when it sent none.
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
    ) -> Result<(Session, Option<bool>), HandshakeError> {
        // 1. Verify Identity (server pinning — Invariant 1).
        if let Some(expected) = expected_server_key {
            if expected != &server_hello.server_verify_key {
                return Err(HandshakeError::ServerIdentityMismatch);
            }
        }

        // 2. Verify Signature over the transcript. It binds the whole
        // ClientHello (incl. early-data) and PROTOCOL_VARIANT — a fips↔non-fips
        // mismatch, a downgraded `version`, or a tampered/stripped early-data
        // blob fails this check rather than landing a wrong secret (Invariants
        // 7, 10).
        let transcript = HandshakeTranscript {
            protocol_variant: PROTOCOL_VARIANT,
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
        // The protocol version is pinned and orthogonal to the on-wire packet
        // codec; route the same codec the server's `finalize_session` chose.
        session.set_wire_version(2);

        // 5. Derive resumption secret (seeds the NEXT resume / 0-RTT).
        let mut resumption_secret = [0u8; 32];
        let hk = hkdf::Hkdf::<Sha256>::new(None, &shared_secret);
        if hk
            .expand(b"phantom-resumption-secret-v1", &mut resumption_secret)
            .is_ok()
        {
            session.set_resumption_secret(resumption_secret);
        }

        *self.stage.write() = HandshakeStage::Established;

        // 0-RTT verdict: only meaningful when the client actually sent
        // early-data on this connect (`None` otherwise — resolved decision 1 /
        // Invariant 9).
        let early_data_verdict = client_hello
            .early_data
            .as_ref()
            .map(|_| server_hello.early_data_accepted);
        Ok((session, early_data_verdict))
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

/// Best-effort decryption of a 0-RTT early-data blob.
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

/// Seal a 0-RTT early-data plaintext for transport inside a
/// `ClientHello.early_data`. Mirror of [`decrypt_early_data`].
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
    /// The peer advertised a build-side [`PROTOCOL_VARIANT`] that does
    /// not match this build's. Today: a fips client meeting a non-fips
    /// server, or vice versa.
    #[error("protocol variant mismatch (expected {expected:?}, received {received:?})")]
    ProtocolVariantMismatch {
        expected: Vec<u8>,
        received: Vec<u8>,
    },
}

impl From<HandshakeError> for CoreError {
    fn from(err: HandshakeError) -> Self {
        CoreError::InternalError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ClientHello` advertising a foreign `PROTOCOL_VARIANT`
    /// (simulating a fips/non-fips cross-mode connect) is rejected by
    /// the server with [`HandshakeError::ProtocolVariantMismatch`]
    /// before any KEM / signature work is done.
    #[tokio::test]
    async fn protocol_variant_mismatch_rejected() {
        let server = HandshakeServer::new().expect("HandshakeServer::new");
        let client = HandshakeClient::new().expect("HandshakeClient::new");
        let client_ip = "127.0.0.1".parse().expect("parse client_ip");

        let mut hello = client.create_client_hello();
        // Pretend the peer was compiled with a different feature set.
        hello.protocol_variant = b"phantom-some-other-mode-1".to_vec();

        let response = server.process_client_hello(&hello, 0, client_ip);
        match response {
            HandshakeResponse::Fail(HandshakeError::ProtocolVariantMismatch {
                expected,
                received,
            }) => {
                assert_eq!(expected, PROTOCOL_VARIANT);
                assert_eq!(received, b"phantom-some-other-mode-1");
            }
            other => panic!("expected ProtocolVariantMismatch, got {other:?}"),
        }
    }

    /// Tampering with the cleartext `protocol_variant` to match the
    /// server's value (an MITM bypass attempt) is caught by the
    /// transcript signature: the transcript still binds the *real*
    /// build-side `PROTOCOL_VARIANT` on each side, so a mixed-mode
    /// signature does not verify. This test exercises the matching
    /// path on the same build (cannot actually run mixed-mode in a
    /// single binary) — we just confirm a normal handshake works
    /// with the variant intact.
    #[tokio::test]
    async fn handshake_succeeds_with_matching_protocol_variant() {
        let server = HandshakeServer::new().expect("HandshakeServer::new");
        let client = HandshakeClient::new().expect("HandshakeClient::new");
        let client_ip = "127.0.0.1".parse().expect("parse client_ip");
        let hello = client.create_client_hello();
        assert_eq!(hello.protocol_variant, PROTOCOL_VARIANT);
        // First round: server demands cookie.
        let response = server.process_client_hello(&hello, 0, client_ip);
        let cookie = match response {
            HandshakeResponse::Retry(r) => r.cookie.expect("cookie"),
            other => panic!("expected retry, got {other:?}"),
        };
        let mut hello_retry = hello.clone();
        hello_retry.cookie = Some(cookie);
        match server.process_client_hello(&hello_retry, 0, client_ip) {
            HandshakeResponse::Success(..) => {}
            other => panic!("expected success, got {other:?}"),
        }
    }

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
            HandshakeResponse::Success(h, s, _) => (h, s),
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
                HandshakeResponse::Success(h, s, _) => (h, s),
                _ => panic!("expected success"),
            };
        let (client_session, _) = client
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
                HandshakeResponse::Success(h, s, _) => (h, s),
                _ => panic!("expected success"),
            };
        let (resume_id, resume_secret) = first_server_session.resumption_hint().unwrap();

        // Second client offers the resume_session_id WITHOUT a cookie.
        // Server should accept immediately (no Retry).
        let second_client = HandshakeClient::new().unwrap();
        let resume_hello =
            second_client.create_client_hello_with_resume(resume_id, &resume_secret, None);
        match server.process_client_hello(&resume_hello, 0, client_ip) {
            HandshakeResponse::Success(..) => {} // expected
            HandshakeResponse::Retry(_) => {
                panic!("resume_session_id should bypass cookie/PoW gate")
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
        let hello = client.create_client_hello_with_resume(bogus_id, &[0u8; 32], None);
        match server.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(_) => {} // expected — normal cookie flow
            other => panic!(
                "expected Retry for unknown resume id, got {:?}",
                matches!(other, HandshakeResponse::Success(..)),
            ),
        }
    }

    // ── 0-RTT early-data ──

    /// Drive a full handshake and return the resumption hint the server
    /// minted for it — the `(session_id, resumption_secret)` a resuming
    /// client needs.
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
            HandshakeResponse::Success(_, session, _) => session.resumption_hint().unwrap(),
            _ => panic!("expected success"),
        }
    }

    #[tokio::test]
    async fn early_data_round_trip() {
        let server = HandshakeServer::new().unwrap();
        let client_ip = "127.0.0.1".parse().unwrap();
        let (resume_id, resume_secret) = first_handshake_for_hint(&server, client_ip);

        // Second connect: resume + a 0-RTT early-data payload folded into the
        // single ClientHello.
        let client = HandshakeClient::new().unwrap();
        let early_payload = b"zero-rtt application bytes";
        let hello =
            client.create_client_hello_with_resume(resume_id, &resume_secret, Some(early_payload));

        match server.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Success(sh, _session, early_data) => {
                assert!(sh.early_data_accepted, "server accepted the early-data");
                assert_eq!(
                    early_data.as_deref(),
                    Some(&early_payload[..]),
                    "server decrypted the exact payload the client sealed"
                );
                // The client verifies the ServerHello and learns the same
                // verdict.
                let (_session, accepted) = client
                    .process_server_hello(&hello, &sh, Some(server.verifying_key()))
                    .expect("client verifies the ServerHello");
                assert_eq!(accepted, Some(true), "client sees early-data accepted");
            }
            other => panic!(
                "expected Success with accepted early-data, got {}",
                match other {
                    HandshakeResponse::Retry(_) => "Retry",
                    HandshakeResponse::Fail(_) => "Fail",
                    HandshakeResponse::Success(..) => unreachable!(),
                }
            ),
        }
    }

    #[tokio::test]
    async fn oversized_early_data_rejected_but_handshake_succeeds() {
        let server = HandshakeServer::new().unwrap();
        let client_ip = "127.0.0.1".parse().unwrap();
        let (resume_id, resume_secret) = first_handshake_for_hint(&server, client_ip);

        // A blob whose sealed length exceeds EARLY_DATA_MAX_LEN + tag.
        let huge = vec![0u8; EARLY_DATA_MAX_LEN + 1];
        let client = HandshakeClient::new().unwrap();
        let hello = client.create_client_hello_with_resume(resume_id, &resume_secret, Some(&huge));

        match server.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Success(sh, _session, early_data) => {
                assert!(!sh.early_data_accepted, "oversized blob rejected");
                assert!(early_data.is_none(), "no plaintext surfaces");
            }
            _ => panic!("handshake must still succeed as 1-RTT"),
        }
    }

    #[tokio::test]
    async fn corrupted_early_data_rejected_but_handshake_succeeds() {
        let server = HandshakeServer::new().unwrap();
        let client_ip = "127.0.0.1".parse().unwrap();
        let (resume_id, resume_secret) = first_handshake_for_hint(&server, client_ip);

        // Build a resume ClientHello, then replace the sealed blob with
        // in-range garbage — AEAD verification must fail.
        let client = HandshakeClient::new().unwrap();
        let mut hello = client.create_client_hello_with_resume(resume_id, &resume_secret, None);
        hello.early_data = Some(vec![0xFFu8; 128]);

        match server.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Success(sh, _session, early_data) => {
                assert!(!sh.early_data_accepted, "AEAD failure → rejected");
                assert!(early_data.is_none());
            }
            _ => panic!("handshake must still succeed as 1-RTT"),
        }
    }

    #[tokio::test]
    async fn unknown_ticket_with_early_data_falls_back_to_cookie_retry() {
        // A ClientHello whose resume_session_id the server has never seen
        // gets no cookie/PoW bypass — and with no cookie attached, the server
        // demands one via Retry. The undecryptable early-data is ignored.
        let server = HandshakeServer::new().unwrap();
        let client_ip = "127.0.0.1".parse().unwrap();
        let client = HandshakeClient::new().unwrap();
        let hello = client.create_client_hello_with_resume([0xAB; 32], &[0xCD; 32], Some(b"hi"));
        assert!(
            matches!(
                server.process_client_hello(&hello, 0, client_ip),
                HandshakeResponse::Retry(_)
            ),
            "unknown ticket → no bypass → cookie Retry"
        );
    }
}
