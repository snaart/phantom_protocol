//! Multi-path / connection migration state (Phase 4.2).
//!
//! Tracks the per-path lifecycle from "newly observed" through
//! "validated" so the session can refuse to send application data over
//! an unverified path. Each path is identified by the 1-byte
//! `path_id` field in `PacketHeader` (Phase 3.3 / Phase 4.2 wire
//! addition).
//!
//! ## Validation protocol
//!
//! When a peer arrives on a new (session_id, path_id) tuple — a fresh
//! UDP source IP, a different transport leg, whatever — the receiver
//! MUST NOT trust the path for application data until it has proven
//! reachability by completing a challenge-response round-trip:
//!
//! 1. Receiver registers the new `path_id` (state: `Unvalidated`).
//! 2. Receiver calls [`PathRegistry::issue_challenge`] to allocate a
//!    fresh 32-byte random challenge, stored under the `path_id`. The
//!    state transitions to `Validating`.
//! 3. Receiver sends a `PATH_VALIDATION` flagged packet on the new
//!    path carrying the challenge bytes as its payload.
//! 4. The legitimate peer echoes the same bytes back in a
//!    `PATH_VALIDATION` packet (the AEAD authentication guarantees
//!    only the legitimate peer who holds the session key can do this).
//! 5. Receiver calls [`PathRegistry::verify_response`]. If the bytes
//!    match the stored challenge, the path transitions to `Validated`
//!    and may carry application data. A mismatch transitions to
//!    `Failed`.
//!
//! The cryptographic protection comes from the AEAD layer: a network
//! attacker observing the wire cannot forge a `PATH_VALIDATION` packet
//! with the right payload because they don't hold the session AEAD key.
//! The challenge bytes themselves don't need to be secret — they exist
//! to bind a specific path-validation attempt to a specific response.
//!
//! ## Use against migration
//!
//! When a peer's source IP changes mid-session (mobile handoff,
//! LTE↔Wi-Fi switch, multi-path), the session must NOT silently
//! accept packets on the new path — that would let an attacker hijack
//! by spoofing the source IP. Issuing a challenge on the new path
//! before accepting traffic forces the attacker to also hold the
//! AEAD key, which they don't.

use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use subtle::ConstantTimeEq;

use crate::crypto::rng::{OsRng, RngProvider};

/// Width of a path-validation challenge / response, in bytes.
pub const PATH_CHALLENGE_LEN: usize = 32;

/// Lifecycle state of a single path within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStateKind {
    /// First seen but never sent / received a validation challenge.
    /// Application data MUST NOT be sent on or accepted from this
    /// path while in this state.
    Unvalidated,
    /// Validation challenge has been issued; awaiting a matching
    /// response. Application data MUST NOT cross until `Validated`.
    Validating,
    /// Path has completed challenge-response. Application data is
    /// allowed.
    Validated,
    /// Path validation failed (wrong response, timeout, etc.). Path
    /// is permanently disabled within this session — the peer must
    /// re-register from `Unvalidated`.
    Failed,
}

/// Per-path bookkeeping. Lives inside [`PathRegistry`].
pub struct PathState {
    pub path_id: u8,
    state: AtomicU8, // PathStateKind as u8
    /// EMA-smoothed RTT estimate for this path, in milliseconds.
    /// Updated by the scheduler / data pump as ACKs land.
    pub rtt_ms: AtomicU32,
    /// Smoothed loss percentage (0-100) for this path.
    pub loss_pct: AtomicU8,
    /// Wall-clock instant of the most recent packet observed on this
    /// path. Used by the timeout sweep.
    pub last_packet_seen: RwLock<Option<Instant>>,
    /// 32-byte challenge associated with the in-flight validation
    /// attempt. `None` outside `Validating`.
    pending_challenge: Mutex<Option<[u8; PATH_CHALLENGE_LEN]>>,
}

impl PathState {
    fn new(path_id: u8) -> Self {
        Self {
            path_id,
            state: AtomicU8::new(PathStateKind::Unvalidated as u8),
            rtt_ms: AtomicU32::new(0),
            loss_pct: AtomicU8::new(0),
            last_packet_seen: RwLock::new(None),
            pending_challenge: Mutex::new(None),
        }
    }

    pub fn state(&self) -> PathStateKind {
        match self.state.load(Ordering::Acquire) {
            0 => PathStateKind::Unvalidated,
            1 => PathStateKind::Validating,
            2 => PathStateKind::Validated,
            3 => PathStateKind::Failed,
            // Bit-rot insurance: never trust a malformed state byte.
            _ => PathStateKind::Failed,
        }
    }

    fn set_state(&self, new: PathStateKind) {
        self.state.store(new as u8, Ordering::Release);
    }

    /// Mark this path as having just observed a packet. Updates the
    /// `last_packet_seen` timestamp; cheap enough to call per-packet.
    pub fn mark_seen(&self) {
        *self.last_packet_seen.write() = Some(Instant::now());
    }
}

/// Per-session collection of [`PathState`]s indexed by `path_id`.
///
/// Lock-free in the steady state (DashMap is lock-free for reads);
/// per-path validation operations take only the per-path `Mutex` on
/// the pending challenge, which is uncontended outside of the brief
/// window of an active challenge round-trip.
pub struct PathRegistry {
    paths: DashMap<u8, PathState>,
}

/// Outcome of a [`PathRegistry::register`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationResult {
    /// Path was newly created — caller should issue a challenge.
    Created,
    /// Path was already present. No state change.
    AlreadyKnown,
}

impl Default for PathRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PathRegistry {
    pub fn new() -> Self {
        Self {
            paths: DashMap::new(),
        }
    }

    /// Register a new path id if it doesn't already exist. Returns
    /// `Created` if this call created the entry — caller is the one
    /// that should now issue a validation challenge.
    pub fn register(&self, path_id: u8) -> RegistrationResult {
        // DashMap::insert returns the previous value. We use entry
        // semantics so we don't overwrite an existing PathState.
        let mut created = false;
        self.paths.entry(path_id).or_insert_with(|| {
            created = true;
            PathState::new(path_id)
        });
        if created {
            RegistrationResult::Created
        } else {
            RegistrationResult::AlreadyKnown
        }
    }

    /// Register a new path id directly in the `Validated` state, skipping
    /// the challenge-response round trip. Used for the implicit
    /// `path_id = 0` initialised at session establishment — that path
    /// is the one the handshake itself traversed, so the AEAD setup
    /// itself was already a stronger proof of reachability than any
    /// PATH_CHALLENGE would be.
    ///
    /// Returns `Created` if this call created the entry. If the entry
    /// already existed, its state is NOT modified — the caller must
    /// explicitly drive a challenge-response if they want to change it.
    pub fn register_validated(&self, path_id: u8) -> RegistrationResult {
        let mut created = false;
        self.paths.entry(path_id).or_insert_with(|| {
            created = true;
            let p = PathState::new(path_id);
            p.set_state(PathStateKind::Validated);
            p
        });
        if created {
            RegistrationResult::Created
        } else {
            RegistrationResult::AlreadyKnown
        }
    }

    /// Update `last_packet_seen` on the path. No-op for unknown paths.
    pub fn mark_seen(&self, path_id: u8) {
        if let Some(p) = self.paths.get(&path_id) {
            p.mark_seen();
        }
    }

    /// Allocate a fresh challenge for the path and transition it to
    /// `Validating`. The caller is responsible for transmitting the
    /// returned bytes (typically inside a `PATH_VALIDATION`-flagged V2
    /// packet).
    ///
    /// Returns `None` if the path is unknown or if it is already in
    /// `Validated` / `Failed` (re-issuing a challenge from those
    /// terminal states is the caller's explicit decision).
    pub fn issue_challenge(&self, path_id: u8) -> Option<[u8; PATH_CHALLENGE_LEN]> {
        let path = self.paths.get(&path_id)?;
        match path.state() {
            PathStateKind::Unvalidated | PathStateKind::Validating => {
                // OK to issue or re-issue.
            }
            PathStateKind::Validated | PathStateKind::Failed => return None,
        }
        // PATH-003: hold the pending-challenge lock across the decision so a
        // re-issue on a path that already has a challenge in flight returns that
        // SAME challenge (idempotent) instead of clobbering it — otherwise a late
        // but valid response to the original challenge would no longer match and
        // would push the path to `Failed`.
        let mut pending = path.pending_challenge.lock();
        if let Some(existing) = *pending {
            return Some(existing);
        }
        // Draw the challenge from the `OsRng` seam (SUPPLY-04b). Under
        // `--features fips` this routes through aws-lc-rs's CTR_DRBG; otherwise
        // `getrandom`. The seam owns the inventoried getrandom-failure
        // PANIC-SAFETY contract, so we add no fresh `unwrap`/`expect` here. A
        // server-issued path challenge is security-sensitive (Invariant 6), so
        // it must come from the CSPRNG, not a non-cryptographic source.
        let mut challenge = [0u8; PATH_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut challenge);
        *pending = Some(challenge);
        drop(pending);
        path.set_state(PathStateKind::Validating);
        Some(challenge)
    }

    /// Verify a peer's response to a previously-issued challenge. On a
    /// constant-time match, transitions the path to `Validated` and
    /// returns `true`. On mismatch or unknown state, transitions to
    /// `Failed` and returns `false`. On unknown path, returns `false`
    /// without side-effects.
    ///
    /// `subtle::ConstantTimeEq` is used so a timing observer cannot
    /// distinguish "wrong byte at position 0" from "wrong byte at
    /// position 31" — same posture as the cookie check in
    /// `transport::handshake::validate_cookie`.
    pub fn verify_response(&self, path_id: u8, response: &[u8]) -> bool {
        let path = match self.paths.get(&path_id) {
            Some(p) => p,
            None => return false,
        };
        if response.len() != PATH_CHALLENGE_LEN {
            return false;
        }
        if path.state() != PathStateKind::Validating {
            return false;
        }
        let mut guard = path.pending_challenge.lock();
        let expected = match guard.take() {
            Some(e) => e,
            None => {
                // Validating state without a pending challenge is
                // inconsistent — fail closed.
                drop(guard);
                path.set_state(PathStateKind::Failed);
                return false;
            }
        };
        drop(guard);
        let matched: bool = expected.ct_eq(response).into();
        if matched {
            path.set_state(PathStateKind::Validated);
            true
        } else {
            path.set_state(PathStateKind::Failed);
            false
        }
    }

    /// Current state of a path. Returns `None` for unknown ids.
    pub fn state(&self, path_id: u8) -> Option<PathStateKind> {
        self.paths.get(&path_id).map(|p| p.state())
    }

    /// Snapshot of all path ids currently in `Validated`.
    pub fn validated_paths(&self) -> Vec<u8> {
        self.paths
            .iter()
            .filter(|p| p.state() == PathStateKind::Validated)
            .map(|p| *p.key())
            .collect()
    }

    /// Number of paths in any state.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_new_path_returns_created() {
        let r = PathRegistry::new();
        assert_eq!(r.register(7), RegistrationResult::Created);
        assert_eq!(r.register(7), RegistrationResult::AlreadyKnown);
    }

    #[test]
    fn freshly_registered_path_is_unvalidated() {
        let r = PathRegistry::new();
        r.register(1);
        assert_eq!(r.state(1), Some(PathStateKind::Unvalidated));
    }

    #[test]
    fn issue_challenge_transitions_to_validating() {
        let r = PathRegistry::new();
        r.register(1);
        let challenge = r.issue_challenge(1).expect("challenge issued");
        assert_eq!(challenge.len(), PATH_CHALLENGE_LEN);
        assert_eq!(r.state(1), Some(PathStateKind::Validating));
    }

    #[test]
    fn reissue_on_validating_path_returns_same_challenge() {
        // PATH-003: a second issue_challenge while one is already in flight must
        // return the SAME challenge, not mint+install a fresh one (which would
        // invalidate a legitimate response to the original and push the path to
        // Failed). Idempotency across the Unvalidated/Validating window.
        let r = PathRegistry::new();
        r.register(1);
        let first = r.issue_challenge(1).expect("first challenge");
        let second = r.issue_challenge(1).expect("re-issue returns existing");
        assert_eq!(
            first, second,
            "re-issue must not clobber the in-flight challenge"
        );
        // The original challenge still verifies (it was never overwritten).
        assert!(r.verify_response(1, &first));
        assert_eq!(r.state(1), Some(PathStateKind::Validated));
    }

    #[test]
    fn matching_response_transitions_to_validated() {
        let r = PathRegistry::new();
        r.register(1);
        let challenge = r.issue_challenge(1).expect("challenge");
        assert!(r.verify_response(1, &challenge));
        assert_eq!(r.state(1), Some(PathStateKind::Validated));
    }

    #[test]
    fn mismatched_response_transitions_to_failed() {
        let r = PathRegistry::new();
        r.register(1);
        let mut challenge = r.issue_challenge(1).expect("challenge");
        challenge[0] ^= 0xFF; // flip a byte
        assert!(!r.verify_response(1, &challenge));
        assert_eq!(r.state(1), Some(PathStateKind::Failed));
    }

    #[test]
    fn response_without_challenge_fails() {
        let r = PathRegistry::new();
        r.register(1);
        // Bypass issue_challenge — try to verify against nothing.
        let zeros = [0u8; PATH_CHALLENGE_LEN];
        assert!(!r.verify_response(1, &zeros));
        // State stays Unvalidated since we never went into Validating.
        assert_eq!(r.state(1), Some(PathStateKind::Unvalidated));
    }

    #[test]
    fn response_for_wrong_length_fails() {
        let r = PathRegistry::new();
        r.register(1);
        let _ = r.issue_challenge(1);
        assert!(!r.verify_response(1, &[0u8; 16])); // wrong length
                                                    // The path remains in Validating — short response is not a
                                                    // failed validation, it's a malformed packet that doesn't even
                                                    // get to the equality check.
        assert_eq!(r.state(1), Some(PathStateKind::Validating));
    }

    #[test]
    fn issue_challenge_on_unknown_path_returns_none() {
        let r = PathRegistry::new();
        assert!(r.issue_challenge(99).is_none());
    }

    #[test]
    fn validated_paths_lists_only_validated() {
        let r = PathRegistry::new();
        for p in 0..5 {
            r.register(p);
        }
        // Validate paths 1 and 3.
        for p in [1u8, 3].iter().copied() {
            let c = r.issue_challenge(p).unwrap();
            assert!(r.verify_response(p, &c));
        }
        // Path 2: issue but fail.
        let mut c = r.issue_challenge(2).unwrap();
        c[0] ^= 1;
        assert!(!r.verify_response(2, &c));
        // Path 4: leave Validating.
        r.issue_challenge(4);

        let mut validated = r.validated_paths();
        validated.sort();
        assert_eq!(validated, vec![1, 3]);
    }

    #[test]
    fn mark_seen_updates_last_packet_timestamp() {
        let r = PathRegistry::new();
        r.register(1);
        // Sleep briefly to make the before/after distinguishable.
        let before = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        r.mark_seen(1);
        let path = r.paths.get(&1).unwrap();
        let seen = path.last_packet_seen.read().expect("set");
        assert!(seen >= before);
    }

    #[test]
    fn re_validating_terminal_path_returns_none() {
        let r = PathRegistry::new();
        r.register(1);
        let c = r.issue_challenge(1).unwrap();
        assert!(r.verify_response(1, &c)); // Validated.

        // Re-issuing on a Validated path is refused.
        assert!(r.issue_challenge(1).is_none());

        // Same for Failed.
        r.register(2);
        let mut c2 = r.issue_challenge(2).unwrap();
        c2[0] ^= 1;
        assert!(!r.verify_response(2, &c2)); // Failed.
        assert!(r.issue_challenge(2).is_none());
    }
}
