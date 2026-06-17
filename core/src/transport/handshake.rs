//! Unified Phantom Protocol Handshake
//!
//! Combines PQC security (Hybrid KEM/Sign) with Staged state machine
//! for optimistic start, Early Data, and 0-RTT resumption.

use borsh::{BorshDeserialize, BorshSerialize};
use hmac::{Hmac, KeyInit, Mac};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use crate::crypto::adaptive_crypto::{CipherSuite, CryptoSession};
use crate::crypto::hybrid_kem::{HybridCiphertext, HybridKeyPackage, HybridSecretKey};
use crate::crypto::hybrid_sign::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::crypto::kdf::derive_early_data_keying;
use crate::crypto::pow::{PoWChallenge, PoWSolution};
use crate::errors::CoreError;
use crate::transport::reputation::ReputationTracker;
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
pub const PROTOCOL_VERSION: u8 = 3;

/// Marker leading a [`ServerReject`] frame. The client disambiguates the three
/// possible server replies by trial-deserialization; the marker (plus the
/// fixed, tiny size of a reject vs. the multi-KiB `ServerHello`) makes a reject
/// unmistakable and immune to a false-positive parse as a `HelloRetryRequest`.
pub const SERVER_REJECT_MARKER: [u8; 4] = *b"PRJ1";

/// [`ServerReject::code`]: the client's `ClientHello.version` is one this server
/// does not speak. `supported_version` carries the version it *does* speak.
pub const REJECT_UNSUPPORTED_VERSION: u8 = 1;

/// Typed handshake rejection the server returns *instead of* silently dropping
/// the connection when it structurally cannot satisfy a `ClientHello` — today,
/// an unknown `version`. It gives a forward/backward-incompatible peer an
/// actionable signal (the version the server speaks) rather than a bare
/// connection reset.
///
/// **Downgrade safety.** The client surfaces a reject as a hard error and does
/// **not** auto-retry at the advertised version. Auto-downgrading on an
/// attacker-injected reject would defeat the transcript-bound downgrade
/// resistance of Invariant 7 (the version is signed into the transcript). The
/// reject is diagnostic only; protocol selection stays pinned.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerReject {
    /// Always [`SERVER_REJECT_MARKER`]; lets the client identify the frame.
    pub marker: [u8; 4],
    /// Reject reason — see [`REJECT_UNSUPPORTED_VERSION`].
    pub code: u8,
    /// The `PROTOCOL_VERSION` this server speaks.
    pub supported_version: u8,
}

impl ServerReject {
    /// Build the unsupported-version reject advertising this build's
    /// [`PROTOCOL_VERSION`].
    pub fn unsupported_version() -> Self {
        Self {
            marker: SERVER_REJECT_MARKER,
            code: REJECT_UNSUPPORTED_VERSION,
            supported_version: PROTOCOL_VERSION,
        }
    }

    /// True iff the frame carries the reject marker — the client's guard
    /// against treating a same-sized non-reject blob as a reject.
    pub fn has_marker(&self) -> bool {
        self.marker == SERVER_REJECT_MARKER
    }
}

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
    /// Resumption proof-of-possession binder (HS-03). Present iff
    /// `resume_session_id` is — a keyed PRF over `resumption_secret ||
    /// resume_session_id || nonce` (see `derive_resumption_binder`). The server
    /// verifies it (constant-time) against the cached ticket's secret *before*
    /// consuming the one-shot ticket, so a passive observer that copied the
    /// cleartext `resume_session_id` cannot burn a victim's ticket. Bound into
    /// the transcript (the whole `ClientHello` is signed), so it is also
    /// tamper-evident. Placed after `resume_session_id` and before
    /// `protocol_variant` — borsh field order is wire-load-bearing.
    pub resumption_binder: Option<[u8; 32]>,
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

/// Real maximum byte lengths of the variable-length `ClientHello` fields (M-7). The ML-KEM-768
/// encapsulation key is 1184 B and the ML-DSA-65 verifying key 1952 B — both fixed by FIPS
/// 203 / 204, independent of the classical/fips build — and the `PROTOCOL_VARIANT` tag is well
/// under 32 B; 0-RTT early-data is capped at [`EARLY_DATA_MAX_LEN`].
const ML_KEM_PK_MAX: usize = 1184;
const ML_DSA_PK_MAX: usize = 1952;
const PROTOCOL_VARIANT_MAX: usize = 64;

/// Structural length pre-check for a borsh-encoded [`ClientHello`] (M-7). Walks the frozen
/// borsh field layout reading ONLY the `Vec<u8>` length prefixes (u32 little-endian) and the
/// 1-byte `Option` tags, validating each variable field against its real maximum WITHOUT
/// allocating — so a forged length (e.g. `0xFFFF_FFFF` on `ml_kem_pk`) is rejected before
/// `borsh::from_slice` performs its `vec![0u8; len.min(1 MiB)]` eager allocate+memset. Returns
/// `false` on any out-of-bounds length, truncation, or trailing bytes; the caller then drops
/// the frame.
///
/// NOTE: coupled to the `ClientHello` borsh layout (frozen by `core/tests/wire_vectors`). A
/// field-order/type change must update this AND the vectors together; the unit test feeds a
/// real `create_client_hello()` through it, so a layout drift that breaks a genuine hello is
/// caught here as a hard red.
pub(crate) fn client_hello_lengths_within_bounds(bytes: &[u8]) -> bool {
    /// Advance `pos` by `n` fixed bytes; false on truncation.
    fn skip(bytes: &[u8], pos: &mut usize, n: usize) -> bool {
        match pos.checked_add(n) {
            Some(end) if end <= bytes.len() => {
                *pos = end;
                true
            }
            _ => false,
        }
    }
    /// Read a borsh u32 length prefix (little-endian); `None` on truncation.
    fn read_len(bytes: &[u8], pos: &mut usize) -> Option<usize> {
        let end = pos.checked_add(4)?;
        if end > bytes.len() {
            return None;
        }
        let l = u32::from_le_bytes([
            bytes[*pos],
            bytes[*pos + 1],
            bytes[*pos + 2],
            bytes[*pos + 3],
        ]);
        *pos = end;
        Some(l as usize)
    }
    /// Read a borsh `Option` tag (1 byte: 0 = None, 1 = Some); `None` on a bad tag/truncation.
    fn read_opt(bytes: &[u8], pos: &mut usize) -> Option<bool> {
        let tag = *bytes.get(*pos)?;
        *pos += 1;
        match tag {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
    /// Validate a length-prefixed `Vec<u8>` whose length must be `<= max`.
    fn vec_le(bytes: &[u8], pos: &mut usize, max: usize) -> bool {
        match read_len(bytes, pos) {
            Some(l) if l <= max => skip(bytes, pos, l),
            _ => false,
        }
    }
    /// Validate an `Option<[u8; n]>` fixed-size field.
    fn opt_fixed(bytes: &[u8], pos: &mut usize, n: usize) -> bool {
        match read_opt(bytes, pos) {
            Some(true) => skip(bytes, pos, n),
            Some(false) => true,
            None => false,
        }
    }

    let mut pos = 0usize;
    // client_key_package: classical_pk [u8; CLASSICAL_PK_BYTES] ++ ml_kem_pk Vec<u8>
    if !skip(
        bytes,
        &mut pos,
        crate::crypto::hybrid_kem::CLASSICAL_PK_BYTES,
    ) || !vec_le(bytes, &mut pos, ML_KEM_PK_MAX)
    {
        return false;
    }
    // client_verify_key: ed25519_pk [u8; 32] ++ ml_dsa_pk Vec<u8>
    if !skip(bytes, &mut pos, 32) || !vec_le(bytes, &mut pos, ML_DSA_PK_MAX) {
        return false;
    }
    // nonce [u8; 32] ++ version u8
    if !skip(bytes, &mut pos, 32 + 1) {
        return false;
    }
    // cookie Option<[u8;32]>, pow_solution Option<PoWSolution = [u8;32] ++ u64 = 40 B>,
    // resume_session_id Option<[u8;32]>, resumption_binder Option<[u8;32]>
    if !opt_fixed(bytes, &mut pos, 32)
        || !opt_fixed(bytes, &mut pos, 40)
        || !opt_fixed(bytes, &mut pos, 32)
        || !opt_fixed(bytes, &mut pos, 32)
    {
        return false;
    }
    // protocol_variant Vec<u8>
    if !vec_le(bytes, &mut pos, PROTOCOL_VARIANT_MAX) {
        return false;
    }
    // early_data Option<Vec<u8>>
    match read_opt(bytes, &mut pos) {
        Some(true) => {
            if !vec_le(bytes, &mut pos, EARLY_DATA_MAX_LEN) {
                return false;
            }
        }
        Some(false) => {}
        None => return false,
    }
    // Exactly consumed: a well-formed, bounded ClientHello. Trailing bytes = malformed
    // (borsh::from_slice itself rejects trailing data).
    pos == bytes.len()
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
    /// Reject: the server structurally cannot speak this `ClientHello` (e.g. an
    /// unknown `version`). Unlike `Fail`, the listener serialises the carried
    /// [`ServerReject`] back to the client before closing, so the peer gets a
    /// typed downgrade signal instead of a bare connection error.
    Reject(ServerReject),
    /// Fail: Handshake aborted
    Fail(HandshakeError),
}

/// Hello Retry Request (Server demands PoW or Cookie)
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HelloRetryRequest {
    pub challenge: Option<PoWChallenge>,
    pub cookie: Option<[u8; 32]>,
}

/// Outcome of the UDP demux address-validation pre-gate
/// ([`HandshakeServer::udp_admit`], H-2).
pub(crate) enum UdpAdmit {
    /// The hello carries a valid IP-bound cookie — the caller may allocate a slot.
    Admit,
    /// No/invalid cookie — reply with this stateless cookie demand; commit no slot.
    Retry(HelloRetryRequest),
    /// Internal cookie-generation failure — drop without reply.
    Drop,
}

/// Server hello message (response to ClientHello)
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ServerHello {
    /// Server-contributed 32-byte nonce (T4.3). Replaces the former ~1184 B
    /// `server_key_package` — a full ML-KEM key package whose KEM secret was discarded
    /// (the protocol runs no second KEM round). It is bound into the signed transcript,
    /// so it remains a session-specific, tamper-evident server contribution beyond
    /// `session_id` + the client nonce; a future second-KEM ring could repurpose this
    /// slot. Saves ~1.1 KB on every ServerHello.
    pub server_nonce: [u8; 32],
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

/// A discriminated server handshake reply (T4.4).
///
/// The wire form is `[kind: u8] ‖ borsh(body)`. The leading discriminant byte lets the
/// client dispatch the three possible replies **explicitly**, instead of the former
/// trial-deserialization that distinguished them by message size (a `ServerReject` is a
/// handful of bytes, a `HelloRetryRequest` tens, a `ServerHello` thousands — robust in
/// practice, but a same-size confusion was structurally possible). The discriminant is an
/// API-layer framing byte that sits *outside* the borsh message structs, so it does not
/// affect the frozen `wire_vectors` (which fix the bare message encodings).
// `ServerReply` is a transient wire-framing wrapper: it is constructed once per handshake
// reply, immediately `to_wire`/`from_wire`'d, then dropped — never stored or passed in bulk.
// The `Hello` variant is intrinsically large (the multi-KiB signed `ServerHello`); boxing it
// would add a heap allocation to every reply for no real benefit at this lifetime.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum ServerReply {
    /// Handshake succeeded — carries the signed [`ServerHello`].
    Hello(ServerHello),
    /// DoS gate — carries a cookie / PoW [`HelloRetryRequest`].
    Retry(HelloRetryRequest),
    /// Structural rejection (e.g. unknown `version`) — carries a [`ServerReject`].
    Reject(ServerReject),
}

impl ServerReply {
    const KIND_HELLO: u8 = 0;
    const KIND_RETRY: u8 = 1;
    const KIND_REJECT: u8 = 2;

    /// Serialise to `[kind: u8] ‖ borsh(body)`.
    pub fn to_wire(&self) -> Result<Vec<u8>, HandshakeError> {
        let map = |e: borsh::io::Error| HandshakeError::SerializationError(e.to_string());
        let (kind, body) = match self {
            ServerReply::Hello(h) => (Self::KIND_HELLO, borsh::to_vec(h).map_err(map)?),
            ServerReply::Retry(r) => (Self::KIND_RETRY, borsh::to_vec(r).map_err(map)?),
            ServerReply::Reject(r) => (Self::KIND_REJECT, borsh::to_vec(r).map_err(map)?),
        };
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(kind);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parse `[kind: u8] ‖ borsh(body)` with explicit dispatch on the discriminant. An
    /// empty input or an unknown kind byte is an error — never a silent misparse.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, HandshakeError> {
        let (&kind, body) = bytes
            .split_first()
            .ok_or_else(|| HandshakeError::SerializationError("empty server reply".into()))?;
        let map = |e: borsh::io::Error| HandshakeError::SerializationError(e.to_string());
        match kind {
            Self::KIND_HELLO => Ok(ServerReply::Hello(borsh::from_slice(body).map_err(map)?)),
            Self::KIND_RETRY => Ok(ServerReply::Retry(borsh::from_slice(body).map_err(map)?)),
            Self::KIND_REJECT => Ok(ServerReply::Reject(borsh::from_slice(body).map_err(map)?)),
            other => Err(HandshakeError::SerializationError(format!(
                "unknown server-reply discriminant {other}"
            ))),
        }
    }
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
    server_nonce: &'a [u8; 32],
    ciphertext: &'a HybridCiphertext,
    server_verify_key: &'a HybridVerifyingKey,
    session_id: &'a [u8; 32],
    /// The server's 0-RTT verdict (H2). Signing it stops an on-path attacker
    /// from flipping `ServerHello.early_data_accepted` to make the client
    /// duplicate or silently drop early-data (Invariant 9). Placed LAST so
    /// `protocol_variant` stays the leading transcript field (Invariant 10).
    early_data_accepted: bool,
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

/// A resumption ticket that the resume fast-path has eagerly consumed after a
/// successful binder check (HS-03 / ZERORTT-2). Carries everything needed to
/// re-insert the ticket **unchanged** (preserving its original lifetime) if a
/// later handshake step fails, so a corrupted resuming `ClientHello` cannot burn
/// a victim's one-shot ticket.
struct ConsumedTicket {
    rid: [u8; 32],
    secret: [u8; 32],
    suite: CipherSuite,
    created_at: std::time::Instant,
    expires_at: std::time::Instant,
}

/// Derive the HS-03 resumption proof-of-possession binder: a keyed PRF over
/// `resumption_secret || resume_session_id || client_nonce` via
/// [`crate::crypto::kdf::derive_key_32`] (blake3 on default builds, HKDF-SHA256
/// under `--features fips`). Binding the per-connect `client_nonce` makes the
/// binder connect-specific; keying it on the secret means only a client that
/// actually holds `resumption_secret` — not a passive observer of the cleartext
/// `resume_session_id` — can produce a value the server will accept.
fn derive_resumption_binder(
    resumption_secret: &[u8; 32],
    resume_session_id: &[u8; 32],
    client_nonce: &[u8; 32],
) -> [u8; 32] {
    // The IKM holds the resumption secret; wipe it on every exit path.
    let mut ikm = zeroize::Zeroizing::new([0u8; 96]);
    ikm[..32].copy_from_slice(resumption_secret);
    ikm[32..64].copy_from_slice(resume_session_id);
    ikm[64..].copy_from_slice(client_nonce);
    crate::crypto::kdf::derive_key_32("phantom-resume-binder-v1", &*ikm)
}

/// Handshake Server State Machine
///
/// Holds the server's long-lived signing key (via [`HybridSigningKey`], which
/// itself zeroes on drop) and a *master* secret from which the actually-used
/// per-hour PoW/cookie secret is derived on each call (see
/// `derive_session_secret_for_hour`). On drop the master is zeroed via the
/// derived `ZeroizeOnDrop`.
///
/// Rotation (Phase 1.11): the master itself rotates only on process restart,
/// but the derived hour-bucketed secret rotates every hour. Validation
/// accepts the current hour and the immediately-previous hour, so a cookie
/// or PoW solution captured at minute 59 of one hour is still honored at
/// minute 5 of the next.
/// Pluggable 0-RTT anti-replay hook — the distributed-deployment seam (A2b).
///
/// The built-in one-shot guarantee (Invariant 9) — a resumption ticket is consumed on first
/// use, so a replayed 0-RTT `ClientHello` finds no ticket and falls back to 1-RTT — holds
/// only under a **single coherent** [`SessionCache`]: one process, or routing that pins a
/// resuming client to the node that minted its ticket. A horizontally-scaled deployment whose
/// nodes each keep their own (or a replicated) cache lets an attacker replay a captured 0-RTT
/// `ClientHello` to a **different** node, which still holds the ticket and would accept the
/// early-data a second time.
///
/// To close that, such a deployment installs a `ZeroRttAntiReplay` backed by a store shared by
/// all nodes (e.g. Redis `SET key NX`, a single-row compare-and-set, a DynamoDB conditional
/// put) via [`HandshakeServer::set_zero_rtt_anti_replay`]. The transport does **not** ship a
/// distributed store — it is the embedder's infrastructure. When none is installed the
/// single-node `SessionCache` is the authority. The orthogonal escape hatch is to disable
/// 0-RTT early-data entirely ([`HandshakeServer::set_early_data_enabled`]).
pub trait ZeroRttAntiReplay: Send + Sync {
    /// Atomically record the first use of resumption ticket `ticket_id` and report whether
    /// THIS call is that first use: `true` if the id had not been seen before (0-RTT may
    /// proceed), `false` if it was already consumed (a replay — the server rejects the
    /// early-data and completes a normal 1-RTT handshake). The implementation MUST be atomic
    /// across every node sharing the resumption cache, and SHOULD retain each consumed id for
    /// at least the ticket lifetime (after which the ticket has expired anyway). Called only
    /// after the resumption proof-of-possession binder has verified (HS-03), so only a holder
    /// of the ticket secret reaches it.
    fn check_and_set(&self, ticket_id: &[u8; 32]) -> bool;
}

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
    /// Per-IP reputation tracker (DOS-2). Drives a PoW-difficulty escalation for
    /// abusive sources on top of the global load tier; bounded map. Holds no
    /// secrets, hence `#[zeroize(skip)]`.
    #[zeroize(skip)]
    reputation: Arc<ReputationTracker>,
    /// Whether 0-RTT early-data is accepted (A2b). `true` by default. When `false`, the server
    /// rejects every resuming client's early-data (`early_data_accepted = false`) so the
    /// payload is only ever delivered 1-RTT — the simplest defence against 0-RTT replay for a
    /// deployment that cannot guarantee a coherent/atomic resumption cache. Resumption itself
    /// (the cookie/PoW bypass) is unaffected; it is replay-safe via the fresh hybrid KEM. Not
    /// secret. Interior-mutable so the embedder can set it on the shared `Arc<HandshakeServer>`.
    #[zeroize(skip)]
    early_data_enabled: AtomicBool,
    /// Optional distributed 0-RTT anti-replay store (A2b). `None` (default) ⇒ the single-node
    /// `SessionCache` is the one-shot authority. `Some` ⇒ the consume is ALSO gated globally
    /// via [`ZeroRttAntiReplay::check_and_set`]. Not secret; a `Mutex<Option<Arc<dyn ..>>>`
    /// (ArcSwap can't hold an unsized `dyn`) so it is settable on the shared
    /// `Arc<HandshakeServer>` — read once per resume (a brief, uncontended lock off the hot path).
    #[zeroize(skip)]
    anti_replay: parking_lot::Mutex<Option<Arc<dyn ZeroRttAntiReplay>>>,
}

impl HandshakeServer {
    pub fn new() -> Result<Self, HandshakeError> {
        // `bind()` without a persisted key mints the server's long-lived identity
        // here — run the FIPS pairwise-consistency check on it (this is a
        // per-process identity, not a per-handshake key, so the cost is paid
        // once at startup).
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        signing_key
            .pairwise_consistency_check(&verifying_key)
            .map_err(|e| {
                HandshakeError::RngError(format!(
                    "server signing identity failed its pairwise-consistency test: {e:?}"
                ))
            })?;
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
            reputation: Arc::new(ReputationTracker::new()),
            early_data_enabled: AtomicBool::new(true),
            anti_replay: parking_lot::Mutex::new(None),
        })
    }

    /// Enable or disable 0-RTT early-data acceptance (A2b). Default enabled. When disabled, the
    /// server rejects every resuming client's early-data (`ServerHello.early_data_accepted =
    /// false`) and completes a normal 1-RTT handshake, so the client resends the payload after
    /// the handshake — the simplest, zero-infrastructure defence against 0-RTT replay for a
    /// deployment that cannot guarantee a single coherent / atomically-consumed resumption
    /// cache. Resumption (the cookie/PoW bypass) is unaffected. Settable on the shared
    /// `Arc<HandshakeServer>` at any time.
    pub fn set_early_data_enabled(&self, enabled: bool) {
        self.early_data_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether 0-RTT early-data acceptance is currently enabled (A2b).
    pub fn early_data_enabled(&self) -> bool {
        self.early_data_enabled.load(Ordering::Relaxed)
    }

    /// Install a distributed 0-RTT anti-replay store (A2b) — see [`ZeroRttAntiReplay`]. Once
    /// installed, a resume is accepted only if the ticket id is first-use according to BOTH the
    /// local `SessionCache` and this store, so a replay to a different node (whose local replica
    /// still holds the ticket) is rejected globally. Required for replay-safe 0-RTT in a
    /// horizontally-scaled deployment; the default (none) is correct for a single node / sticky
    /// routing. Settable on the shared `Arc<HandshakeServer>`.
    pub fn set_zero_rtt_anti_replay(&self, store: Arc<dyn ZeroRttAntiReplay>) {
        *self.anti_replay.lock() = Some(store);
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

    /// Per-IP PoW-difficulty escalation for `client_ip` (DOS-2) — 0 for clean
    /// IPs and resumption-ticket holders, escalating for sources with recent
    /// handshake violations. The server uses
    /// `max(adaptive_difficulty(), reputation_difficulty(...))` so an abusive IP
    /// is singled out even when the global load tier is idle, without penalizing
    /// well-behaved clients.
    pub(crate) fn reputation_difficulty(&self, client_ip: IpAddr, has_ticket: bool) -> u8 {
        self.reputation.calculate_difficulty(client_ip, has_ticket)
    }

    /// Record a handshake violation for `client_ip` (DOS-2) — drives the
    /// escalation. Called on a genuine protocol failure (bad/old/abusive client),
    /// NOT on a normal first-contact cookie/PoW retry.
    pub(crate) fn record_violation(&self, client_ip: IpAddr) {
        self.reputation.record_violation(client_ip);
    }

    /// Clear `client_ip`'s violation record after a successful handshake (DOS-2).
    pub(crate) fn reset_violations(&self, client_ip: IpAddr) {
        self.reputation.reset_violations(client_ip);
    }

    /// Stateless UDP demux address-validation pre-gate (H-2). On the connectionless UDP
    /// path the datagram source is unverified, so a per-connection slot (an `inflight`
    /// permit + a demux route + a handshake task) must not be committed until the source
    /// proves it can receive at its claimed address by echoing a stateless cookie. This
    /// runs only the cookie half of [`Self::cookie_pow_gate`] — cheaply, on the demux
    /// thread, with no KEM/signature work and no committed state — and hands back a cookie
    /// demand otherwise. The PoW/handshake work stays in the per-connection task (post-slot,
    /// for an already address-validated source). Resume tickets do NOT bypass this cookie:
    /// unlike TCP (address-validated by its 3-way handshake), the UDP source is unproven, so
    /// 0-RTT-over-UDP completes a cookie round first.
    pub(crate) fn udp_admit(&self, client_hello: &ClientHello, client_ip: IpAddr) -> UdpAdmit {
        let cookie_valid = match client_hello.cookie {
            Some(c) => validate_cookie(&self.master_secret, client_ip, &c).unwrap_or(false),
            None => false,
        };
        if cookie_valid {
            return UdpAdmit::Admit;
        }
        match generate_cookie(&self.master_secret, client_ip) {
            Ok(cookie) => UdpAdmit::Retry(HelloRetryRequest {
                challenge: None,
                cookie: Some(cookie),
            }),
            Err(_) => UdpAdmit::Drop,
        }
    }

    /// Non-consuming check that `client_hello` carries a VALID 0-RTT resume — its
    /// `resume_session_id` names a still-cached ticket AND the `resumption_binder` proves
    /// possession of that ticket's secret (constant-time). Gates the per-IP PoW-difficulty
    /// reduction on real ticket holders, so attaching a junk `resume_session_id` cannot
    /// nullify the reputation escalation (M-5). Does NOT consume the ticket — the resume fast
    /// path in [`Self::process_client_hello`] still peeks + consumes it.
    pub(crate) fn has_valid_resume(&self, client_hello: &ClientHello) -> bool {
        let Some(rid) = client_hello.resume_session_id else {
            return false;
        };
        let Some((secret, _suite, _created_at, _expires_at)) = self.session_cache.lock().peek(&rid)
        else {
            return false;
        };
        let Some(presented) = client_hello.resumption_binder else {
            return false;
        };
        let expected = derive_resumption_binder(&secret, &rid, &client_hello.nonce);
        bool::from(presented.ct_eq(&expected))
    }

    /// Drop expired reputation entries (DOS-2) — driven periodically by the
    /// listener's acceptor loop.
    pub(crate) fn gc_reputation(&self) {
        self.reputation.gc();
    }

    /// Current per-minute handshake count. Exposed for metrics
    /// (`handshakes_per_minute`).
    pub fn handshakes_this_minute(&self) -> u64 {
        self.handshakes_this_minute.load(Ordering::Relaxed)
    }

    #[tracing::instrument(
        name = "phantom.handshake.process_client_hello",
        skip_all,
        // No `client_ip` field: this span is always-on in the library, and the
        // peer IP is correlatable PII. The DoS gate already has the IP in-band;
        // it does not need to leak into every handshake trace.
        fields(
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
        // (Invariant 7). Instead of dropping silently we hand back a typed
        // `ServerReject` advertising the version we speak, so a future client
        // degrades gracefully (H9 forward-compat) — the client treats it as a
        // hard error and does NOT auto-downgrade, preserving Invariant 7's
        // transcript-bound downgrade resistance.
        if client_hello.version != PROTOCOL_VERSION {
            return HandshakeResponse::Reject(ServerReject::unsupported_version());
        }

        // 0-RTT resumption fast path with proof-of-possession (HS-03 + ZERORTT-2).
        //
        // If the client offered a `resume_session_id` AND the cache holds a
        // still-valid ticket, a valid resume lets the client skip the cookie/PoW
        // DoS gate and (with a sealed blob) deliver 0-RTT early-data.
        //
        // Before trusting the resume we require proof the client holds the
        // ticket's `resumption_secret` — a `resumption_binder` MAC (HS-03). We
        // PEEK the ticket (no consume) to recompute the expected binder and
        // compare it constant-time; a missing/mismatched binder (e.g. a passive
        // observer that only copied the cleartext `resume_session_id`) means NO
        // resume — the ticket is left untouched and the client falls through to
        // the normal cookie/PoW gate.
        //
        // On a valid binder we CONSUME the ticket eagerly (one-shot anti-replay,
        // Invariant 9); `remove` returns `true` for exactly one of two racing
        // duplicate resumes, so the same early-data can't be accepted twice. The
        // consumed ticket is carried in `resumed` and re-inserted unchanged on
        // any later handshake failure (ZERORTT-2), so a corrupted resuming
        // `ClientHello` cannot burn a victim's ticket. The KEM round-trip still
        // runs, so forward secrecy is preserved by the fresh X25519+ML-KEM secret.
        let resumed: Option<ConsumedTicket> = client_hello.resume_session_id.and_then(|rid| {
            let (secret, suite, created_at, expires_at) = self.session_cache.lock().peek(&rid)?;
            // Proof-of-possession: only a holder of `resumption_secret` can
            // produce a binder that matches. `None` binder ⇒ no resume.
            let expected = derive_resumption_binder(&secret, &rid, &client_hello.nonce);
            let presented = client_hello.resumption_binder?;
            if !bool::from(presented.ct_eq(&expected)) {
                return None;
            }
            // Binder verified — consume now (race-free via `remove`'s bool).
            if !self.session_cache.lock().remove(&rid) {
                return None; // a concurrent resume already consumed it on THIS node
            }
            // A2b — when a distributed anti-replay store is installed, the consume must ALSO be
            // first-use GLOBALLY across every node sharing the resumption cache. A replay to a
            // different node, whose local replica still holds the ticket (so `remove` above
            // returned `true`), is caught here and falls back to 1-RTT. (`check_and_set` is the
            // authority; on a later handshake failure the local ticket is re-inserted as before,
            // but the global one-shot is already recorded — a rare infra-failure retry then does
            // 1-RTT, which is acceptable: the ticket is single-use either way.)
            let store = self.anti_replay.lock().clone();
            if let Some(store) = store {
                if !store.check_and_set(&rid) {
                    return None; // already consumed on another node (replay) → no resume
                }
            }
            Some(ConsumedTicket {
                rid,
                secret,
                suite,
                created_at,
                expires_at,
            })
        });
        let cookie_pow_bypass = resumed.is_some();

        // Stateless DoS checks (Cookie & PoW). On the bypass path the gate
        // returns Ok; a rare infra error there is still post-consume, so hand the
        // ticket back if it fails (ZERORTT-2).
        if let Err(resp) =
            self.cookie_pow_gate(client_hello, difficulty, client_ip, cookie_pow_bypass)
        {
            return self.fail_and_reinsert(&resumed, resp);
        }

        // Best-effort 0-RTT early-data decryption. Only attempted when the
        // client both presented a valid ticket AND carried a sealed blob; any
        // failure (unknown/expired ticket, oversized blob, AEAD failure)
        // leaves `early_data_accepted = false` and completes a normal 1-RTT
        // handshake (Invariant 9). Forward secrecy of the post-handshake
        // session is preserved by the fresh hybrid KEM regardless.
        // A2b — when 0-RTT early-data is disabled by config, reject it unconditionally:
        // `early_data_accepted = false`, the resuming client resends the payload 1-RTT. The
        // resume itself (cookie/PoW bypass) still stands; only the early-data is dropped.
        let early_data_plaintext: Option<Vec<u8>> =
            if self.early_data_enabled.load(Ordering::Relaxed) {
                match (&resumed, &client_hello.early_data) {
                    (Some(t), Some(blob)) => {
                        decrypt_early_data(&t.secret, &client_hello.nonce, &t.rid, blob)
                    }
                    _ => None,
                }
            } else {
                None
            };
        let early_data_accepted = early_data_plaintext.is_some();

        // Hybrid Key Exchange (PFS preserved — a fresh KEM secret even on the
        // 0-RTT path).
        let (shared_secret, ciphertext) = match client_hello.client_key_package.encapsulate() {
            // T5.1 — zeroize the transient KEM master on scope exit (it is copied
            // into the now-zeroized `traffic_secret` + `CryptoState` below).
            Ok((ss, ct)) => (zeroize::Zeroizing::new(ss), ct),
            Err(e) => {
                return self.fail_and_reinsert(
                    &resumed,
                    HandshakeResponse::Fail(HandshakeError::KemFailed(e.to_string())),
                );
            }
        };

        // Server-contributed 32-byte nonce (T4.3). Bound into the transcript signature so
        // the server commits to a session-specific value beyond `session_id` + the client
        // nonce. Replaces the former discarded ephemeral KEM key package (~1.1 KB).
        let mut server_nonce = [0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut server_nonce) {
            return self.fail_and_reinsert(
                &resumed,
                HandshakeResponse::Fail(HandshakeError::RngError(e.to_string())),
            );
        }

        let session_id_bytes = derive_session_id(&shared_secret, &client_hello.nonce);
        let session_id = SessionId::from_bytes(session_id_bytes);

        // Sign the transcript. It embeds the WHOLE `ClientHello` (early-data
        // ciphertext included) plus `PROTOCOL_VARIANT` — a tampered or stripped
        // blob breaks the client-side signature check (Invariants 7, 10).
        let transcript = HandshakeTranscript {
            protocol_variant: PROTOCOL_VARIANT,
            client_hello,
            server_nonce: &server_nonce,
            ciphertext: &ciphertext,
            server_verify_key: &self.verifying_key,
            session_id: &session_id_bytes,
            early_data_accepted,
        };
        let transcript_hash = match compute_transcript_hash(&transcript) {
            Ok(h) => h,
            Err(e) => return self.fail_and_reinsert(&resumed, HandshakeResponse::Fail(e)),
        };
        let signature = self.signing_key.sign(&transcript_hash);

        let server_hello = ServerHello {
            server_nonce,
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
            Err(resp) => return self.fail_and_reinsert(&resumed, resp),
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
    /// `shared_secret`: derive the AEAD `CryptoState`, derive + install the
    /// resumption secret, and stash a resumption ticket in the cache.
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

    /// Re-insert a ticket consumed by a resume attempt that then failed
    /// (ZERORTT-2), preserving its original lifetime, and return the failure
    /// response unchanged. A no-op when `resumed` is `None`. This keeps a
    /// corrupted/forged resuming `ClientHello` from burning a victim's one-shot
    /// ticket: the ticket is consumed eagerly (race-free) after the binder check,
    /// and handed back here on every post-consume failure path.
    #[allow(clippy::result_large_err)]
    fn fail_and_reinsert(
        &self,
        resumed: &Option<ConsumedTicket>,
        resp: HandshakeResponse,
    ) -> HandshakeResponse {
        if let Some(t) = resumed {
            self.session_cache.lock().reinsert_with_expiry(
                t.rid,
                &t.secret,
                t.suite,
                t.created_at,
                t.expires_at,
            );
        }
        resp
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
            resumption_binder: None,
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
        // HS-03: prove possession of `resumption_secret` so a passive observer of
        // the cleartext `resume_session_id` cannot consume the server's ticket.
        let resumption_binder =
            derive_resumption_binder(resumption_secret, &resume_session_id, &self.nonce);
        ClientHello {
            client_key_package: self.kem_public.clone(),
            client_verify_key: self.verifying_key.clone(),
            nonce: self.nonce,
            version: PROTOCOL_VERSION,
            cookie: None,
            pow_solution: None,
            resume_session_id: Some(resume_session_id),
            resumption_binder: Some(resumption_binder),
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
            server_nonce: &server_hello.server_nonce,
            ciphertext: &server_hello.ciphertext,
            server_verify_key: &server_hello.server_verify_key,
            session_id: &server_hello.session_id,
            // H2: recompute with the RECEIVED verdict — a flipped bit makes this
            // hash diverge from what the server signed, so verify() below fails.
            early_data_accepted: server_hello.early_data_accepted,
        };
        let transcript_hash = compute_transcript_hash(&transcript)?;
        server_hello
            .server_verify_key
            .verify(&transcript_hash, &server_hello.signature)
            .map_err(|e| HandshakeError::KemFailed(format!("Signature check failed: {:?}", e)))?;

        // 3. Decapsulate
        // T5.1 — zeroize the transient KEM master on scope exit.
        let shared_secret = zeroize::Zeroizing::new(
            self.kem_secret
                .decapsulate(&server_hello.ciphertext)
                .map_err(|e| HandshakeError::KemFailed(e.to_string()))?,
        );

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
            *shared_secret,
            false,
        );

        // 5. Derive resumption secret (seeds the NEXT resume / 0-RTT).
        let mut resumption_secret = [0u8; 32];
        let hk = hkdf::Hkdf::<Sha256>::new(None, &shared_secret[..]);
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

    /// Drain the queued early-data buffer. See [`Self::queue_early_data`] — the
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

    /// Byte-exact freeze of the handshake transcript hash (Phase 6).
    ///
    /// Pins `SHA256(borsh(HandshakeTranscript))` over a fully-deterministic
    /// `ClientHello` + server fields. Unlike the public wire-codec vectors in
    /// `core/tests/wire_vectors.rs`, this exercises the *real* private
    /// `HandshakeTranscript` and `compute_transcript_hash`, so a reorder of the
    /// transcript fields or any change to the hash construction — the signing
    /// input, Invariants 7 & 10 — fails here. The crypto material is
    /// deterministic filler of the real field lengths; the hash needs no live
    /// keys. Default (non-fips) build only (the fips transcript embeds a
    /// different `PROTOCOL_VARIANT` and 65-byte classical key).
    ///
    /// Regenerate alongside the wire vectors with
    /// `PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --lib`.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn transcript_hash_wire_vector() {
        fn pat(seed: u8, n: usize) -> Vec<u8> {
            (0..n).map(|i| seed.wrapping_add(i as u8)).collect()
        }
        fn arr32(seed: u8) -> [u8; 32] {
            pat(seed, 32).try_into().expect("pat(seed, 32) is 32 bytes")
        }

        // Same deterministic filler as the `client_hello_full` / `server_hello`
        // vectors so the three freezes describe one consistent handshake.
        let key_package = HybridKeyPackage {
            classical_pk: arr32(0x10),
            ml_kem_pk: pat(0x20, 1184),
        };
        let verify_key = HybridVerifyingKey {
            ed25519_pk: arr32(0x50),
            ml_dsa_pk: pat(0x60, 1952),
        };
        let client_hello = ClientHello {
            client_key_package: key_package.clone(),
            client_verify_key: verify_key.clone(),
            nonce: arr32(0xA0),
            version: PROTOCOL_VERSION,
            cookie: Some(arr32(0xB0)),
            pow_solution: Some(PoWSolution {
                nonce: arr32(0x90),
                solution: 0x0123_4567_89AB_CDEF,
            }),
            resume_session_id: Some(arr32(0xC0)),
            resumption_binder: Some(arr32(0xC8)),
            protocol_variant: PROTOCOL_VARIANT.to_vec(),
            early_data: Some(pat(0xD0, 48)),
        };
        let ciphertext = HybridCiphertext {
            classical_pk: arr32(0x30),
            ml_kem_ct: pat(0x40, 1088),
        };
        let session_id = arr32(0xE0);

        let transcript = HandshakeTranscript {
            protocol_variant: PROTOCOL_VARIANT,
            client_hello: &client_hello,
            server_nonce: &arr32(0x70),
            ciphertext: &ciphertext,
            server_verify_key: &verify_key,
            session_id: &session_id,
            early_data_accepted: true,
        };
        let hash = compute_transcript_hash(&transcript).expect("transcript hash");

        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/wire_vectors/transcript_hash.bin");
        if std::env::var_os("PHANTOM_REGEN_WIRE_VECTORS").is_some() {
            std::fs::create_dir_all(path.parent().expect("fixtures dir parent"))
                .expect("create wire_vectors dir");
            std::fs::write(&path, hash).expect("write transcript_hash.bin");
            return;
        }
        let expected = std::fs::read(&path)
            .expect("read transcript_hash.bin; regenerate with PHANTOM_REGEN_WIRE_VECTORS=1");
        assert_eq!(
            hash.as_slice(),
            expected.as_slice(),
            "handshake transcript hash changed — the signing input (Invariants 7 & 10) is \
             wire-breaking. If intentional, bump PROTOCOL_VERSION and regenerate."
        );
    }

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

    /// H9 forward-compat: a `ClientHello` advertising a `version` the server
    /// does not speak is answered with a typed [`HandshakeResponse::Reject`]
    /// (carrying the server's supported version), not a silent drop / generic
    /// `Fail`. The reject is produced before any KEM / signature work.
    #[tokio::test]
    async fn unsupported_version_yields_typed_reject() {
        let server = HandshakeServer::new().expect("HandshakeServer::new");
        let client = HandshakeClient::new().expect("HandshakeClient::new");
        let client_ip = "127.0.0.1".parse().expect("parse client_ip");

        let mut hello = client.create_client_hello();
        // A future client speaking a version this build doesn't know.
        hello.version = PROTOCOL_VERSION.wrapping_add(7);

        match server.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Reject(reject) => {
                assert!(reject.has_marker(), "reject must carry the marker");
                assert_eq!(reject.code, REJECT_UNSUPPORTED_VERSION);
                assert_eq!(reject.supported_version, PROTOCOL_VERSION);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    /// T4.4: a server reply carries a leading discriminant byte, so the client dispatches
    /// the three kinds explicitly instead of trial-deserializing by size. Round-trip each
    /// kind, assert the discriminant byte, and reject empty / unknown-kind inputs (never a
    /// silent misparse).
    #[test]
    fn server_reply_discriminant_dispatches_explicitly() {
        // Reject (kind 2).
        let reject = ServerReject::unsupported_version();
        let wire = ServerReply::Reject(reject.clone())
            .to_wire()
            .expect("frame reject");
        assert_eq!(wire[0], 2, "reject discriminant byte");
        assert!(matches!(
            ServerReply::from_wire(&wire),
            Ok(ServerReply::Reject(r)) if r == reject
        ));

        // Retry (kind 1).
        let hrr = HelloRetryRequest {
            challenge: None,
            cookie: Some([7u8; 32]),
        };
        let wire = ServerReply::Retry(hrr.clone())
            .to_wire()
            .expect("frame retry");
        assert_eq!(wire[0], 1, "retry discriminant byte");
        assert!(matches!(
            ServerReply::from_wire(&wire),
            Ok(ServerReply::Retry(r)) if r.cookie == hrr.cookie && r.challenge.is_none()
        ));

        // Unknown discriminant and empty input are errors, not silent misparses.
        assert!(
            ServerReply::from_wire(&[0xFF, 0x00]).is_err(),
            "unknown kind rejected"
        );
        assert!(ServerReply::from_wire(&[]).is_err(), "empty reply rejected");
    }

    /// The reject frame survives a borsh round-trip and is shape-distinct from
    /// a `HelloRetryRequest` (the client's trial-deserialization order relies
    /// on this — a reject must not be mistaken for a retry, nor vice versa).
    #[test]
    fn server_reject_roundtrips_and_is_shape_distinct() {
        let reject = ServerReject::unsupported_version();
        let bytes = borsh::to_vec(&reject).expect("encode reject");
        let decoded: ServerReject = borsh::from_slice(&bytes).expect("decode reject");
        assert_eq!(decoded, reject);
        assert!(decoded.has_marker());

        // A (None, None) HelloRetryRequest must not decode as a reject…
        let hrr = HelloRetryRequest {
            challenge: None,
            cookie: None,
        };
        let hrr_bytes = borsh::to_vec(&hrr).expect("encode hrr");
        assert!(
            borsh::from_slice::<ServerReject>(&hrr_bytes).is_err(),
            "a HelloRetryRequest must not parse as a ServerReject"
        );
        // …and a reject must not decode as a HelloRetryRequest.
        assert!(
            borsh::from_slice::<HelloRetryRequest>(&bytes).is_err(),
            "a ServerReject must not parse as a HelloRetryRequest"
        );
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

    /// T4.3: `server_key_package` (a full ~1184 B ML-KEM key package whose KEM secret
    /// was discarded) is replaced by a 32-byte `server_nonce`. Its sole purpose is to be
    /// a server-contributed, transcript-bound, session-specific value — so flipping it on
    /// the wire must break the client's transcript-signature check (Invariants 7/10),
    /// exactly as the discarded key package did. The positive control rules out a broken
    /// setup masking the negative assertion.
    #[tokio::test]
    async fn server_nonce_is_transcript_bound() {
        let server = HandshakeServer::new().expect("HandshakeServer::new");
        let client = HandshakeClient::new().expect("HandshakeClient::new");
        let client_ip = "127.0.0.1".parse().expect("parse client_ip");

        let hello = client.create_client_hello();
        let cookie = match server.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(r) => r.cookie.expect("cookie"),
            _ => panic!("expected retry"),
        };
        let mut hello_retry = hello.clone();
        hello_retry.cookie = Some(cookie);
        let server_hello = match server.process_client_hello(&hello_retry, 0, client_ip) {
            HandshakeResponse::Success(h, _s, _) => h,
            _ => panic!("expected success"),
        };

        // Positive control: the untampered `server_nonce` verifies + the handshake completes.
        assert!(
            client
                .process_server_hello(&hello_retry, &server_hello, Some(server.verifying_key()))
                .is_ok(),
            "untampered server_nonce must verify"
        );

        // Negative: a flipped `server_nonce` byte makes the recomputed transcript hash
        // diverge from what the server signed → signature check fails (before decapsulate).
        let mut tampered = server_hello.clone();
        tampered.server_nonce[0] ^= 0xFF;
        assert!(
            client
                .process_server_hello(&hello_retry, &tampered, Some(server.verifying_key()))
                .is_err(),
            "a flipped server_nonce byte must fail the transcript-signature check"
        );
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
            HandshakeResponse::Reject(r) => panic!("unexpected reject: {:?}", r),
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
                    HandshakeResponse::Reject(_) => "Reject",
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

    /// **DOS-2.** The `HandshakeServer` wires per-IP reputation: a clean IP (and
    /// a ticket holder) adds no PoW difficulty, repeated violations escalate it,
    /// and a successful-handshake reset clears it.
    #[test]
    fn reputation_wiring_escalates_and_resets_per_ip() {
        let server = HandshakeServer::new().unwrap();
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(
            server.reputation_difficulty(ip, false),
            0,
            "clean IP adds nothing"
        );
        assert_eq!(
            server.reputation_difficulty(ip, true),
            0,
            "ticket holder skips PoW"
        );
        server.record_violation(ip);
        let d1 = server.reputation_difficulty(ip, false);
        assert!(
            d1 >= 8,
            "a violation escalates the per-IP difficulty, got {d1}"
        );
        server.record_violation(ip);
        assert!(
            server.reputation_difficulty(ip, false) >= d1,
            "more violations escalate further"
        );
        server.reset_violations(ip);
        assert_eq!(
            server.reputation_difficulty(ip, false),
            0,
            "reset clears it"
        );
    }

    /// M-7: `client_hello_lengths_within_bounds` must accept a real first-flight ClientHello
    /// but reject a frame whose `ml_kem_pk` length prefix is forged to a huge value — so a
    /// malformed Initial is dropped before `borsh::from_slice` performs its
    /// `vec![0u8; len.min(1 MiB)]` eager allocation (the ~45-byte → 1 MiB amplifier on the
    /// UDP demux / TCP handshake recv).
    #[test]
    fn client_hello_length_validator_rejects_a_forged_vector_length() {
        let hello = HandshakeClient::new()
            .expect("client")
            .create_client_hello();
        let bytes = borsh::to_vec(&hello).expect("serialize");
        assert!(
            client_hello_lengths_within_bounds(&bytes),
            "a real ClientHello must pass the structural length pre-check"
        );

        // Forge the ml_kem_pk length prefix (u32 LE at offset CLASSICAL_PK_BYTES) to 0xFFFFFFFF.
        let mut forged = bytes.clone();
        let off = crate::crypto::hybrid_kem::CLASSICAL_PK_BYTES;
        forged[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            !client_hello_lengths_within_bounds(&forged),
            "a forged ml_kem_pk length must be rejected before borsh allocates"
        );

        // Short garbage / empty frames (what a spoofed Initial carries) are rejected.
        assert!(!client_hello_lengths_within_bounds(b"not-a-clienthello"));
        assert!(!client_hello_lengths_within_bounds(&[]));
    }

    /// M-5 (audit 2026-06-11): the per-IP PoW-difficulty reduction for "ticket holders" must
    /// key on a VALID resume — a cached ticket whose binder verifies — not on mere presence of
    /// a `resume_session_id`. Otherwise a flagged abuser attaches 32 random bytes and pays zero
    /// PoW, nullifying the reputation escalation (DOS-2). `has_valid_resume` is the gate.
    #[test]
    fn has_valid_resume_requires_a_real_ticket_and_binder() {
        let server = HandshakeServer::new().expect("server");
        let server_pk = server.verifying_key().clone();
        let client = HandshakeClient::new().expect("client");
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        // Mint a REAL ticket via a first handshake (answering the one cookie retry).
        let hello1 = client.create_client_hello();
        let (effective, sh) = match server.process_client_hello(&hello1, 0, ip) {
            HandshakeResponse::Retry(r) => {
                let mut h = hello1.clone();
                h.cookie = r.cookie;
                match server.process_client_hello(&h, 0, ip) {
                    HandshakeResponse::Success(sh, _, _) => (h, sh),
                    o => panic!("unexpected after retry: {o:?}"),
                }
            }
            HandshakeResponse::Success(sh, _, _) => (hello1.clone(), sh),
            o => panic!("unexpected first response: {o:?}"),
        };
        let (session, _) = client
            .process_server_hello(&effective, &sh, Some(&server_pk))
            .expect("client establishes a session");
        let secret = session
            .resumption_secret()
            .expect("resumption secret installed");

        // No resume id, and a junk resume id (no cached ticket) are both NOT valid tickets.
        assert!(!server.has_valid_resume(&client.create_client_hello()));
        let mut junk = client.create_client_hello();
        junk.resume_session_id = Some([0x55u8; 32]);
        junk.resumption_binder = Some([0xAAu8; 32]);
        assert!(
            !server.has_valid_resume(&junk),
            "a junk resume_session_id must not count as a valid ticket (M-5)"
        );

        // A flagged IP keeps its elevated PoW difficulty when the resume is junk.
        for _ in 0..5 {
            server.record_violation(ip);
        }
        let flagged = server.reputation_difficulty(ip, false);
        assert!(flagged > 0, "precondition: a flagged IP has difficulty > 0");
        assert_eq!(
            server.reputation_difficulty(ip, server.has_valid_resume(&junk)),
            flagged,
            "a junk resume must not zero a flagged IP's PoW difficulty (M-5)"
        );

        // The real ticket with a valid binder DOES count as a valid resume.
        let resume = client.create_client_hello_with_resume(sh.session_id, &secret, None);
        assert!(
            server.has_valid_resume(&resume),
            "a real cached ticket with a valid binder must count as a valid resume"
        );
    }
}
