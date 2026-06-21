//! Rotating connection-ID chain (introduced in WIRE v5 / ε; current WIRE v6).
//!
//! After v4 header protection, the only per-connection cleartext left on the
//! wire is the outer 8-byte routing `ConnId`. v5 collapsed the two connection
//! identifiers (the redundant 32-byte inner `session_id` is dropped from the
//! data-plane wire) into this single CID and **rotates** it on every migration,
//! closing the stable-CID linkability residual (threat-model §12.5). The v6
//! anti-fingerprint pass did not touch this construction — it still holds.
//!
//! ## Construction
//!
//! At session establishment each peer derives two per-direction chain secrets
//! from the initial session secret (mirroring the AEAD / header-protection key
//! layout):
//!
//! ```text
//! cid_secret_c2s = derive_key_32("phantom-cid-c2s-v1", initial_secret)   // client→server
//! cid_secret_s2c = derive_key_32("phantom-cid-s2c-v1", initial_secret)   // server→client
//! ```
//!
//! The CID for migration index `i` truncates a per-index KDF output to 8 bytes:
//!
//! ```text
//! CID_i = derive_key_32("phantom-cid-v1", cid_secret ‖ i.to_be_bytes())[0..8]
//! ```
//!
//! The client **stamps** its outbound `ConnId` from the c2s chain (the chain the
//! server routes on); the server stamps from the s2c chain. So `is_server` swaps
//! the outbound/inbound secrets, exactly like `HeaderProtector::derive` and the
//! AEAD send/recv keys — one peer's outbound chain is the other's inbound chain.
//!
//! ## Properties
//!
//! - **Session-stable, zeroized:** the chain secrets are derived once and held
//!   for the session (they do not rotate with the AEAD epoch); they are zeroized
//!   on drop. The *index* advances on `migrate()` (held by `Session`, not here).
//! - **Unguessable / unlinkable:** `CID_i` is a KDF output truncation, so without
//!   `cid_secret` the CIDs are independent-random to an observer — pre- and
//!   post-migration flows cannot be linked.
//! - **Not forward-secret (honest caveat):** like the HP keys, a session-key
//!   compromise lets an attacker recompute the whole CID chain and link a
//!   *recorded* flow retroactively. The payload stays forward-secret (AEAD
//!   ratchets). See `docs/plans/wire-v5-cid-collapse-design.md` §5.

use crate::crypto::kdf::derive_key_32;
use zeroize::Zeroize;

/// Wire width of a routing CID (the outer UDP `ConnId`): 8 bytes.
pub const CID_LEN: usize = 8;

/// KDF label for an individual CID: `CID_i = derive_key_32(label, secret ‖ i_be)[0..8]`.
const CID_LABEL: &str = "phantom-cid-v1";
/// Per-direction chain-secret labels. Domain-separated from the AEAD / HP keys.
const CID_C2S_LABEL: &str = "phantom-cid-c2s-v1";
const CID_S2C_LABEL: &str = "phantom-cid-s2c-v1";

/// Default demux window — trailing `T` (in-flight reordering across a migration
/// boundary) and leading `K` (migration lookahead: the sender may have migrated
/// ahead of delivery). `(T + K + 1) = 19` accepted CIDs per inbound direction.
///
/// `K = 16` (audit 2026-06-15, EPS-01): it is the **hard cap on consecutive
/// migrations whose packets are ALL lost** before the sender's CID falls outside
/// the window and the session strands (recoverable by reconnect via the liveness
/// sweep). A delivered migration packet recenters the window on its index (the
/// multi-step slide in `Session::note_migration_path`), so only an unbroken run of
/// `> K` fully-lost migrations strands — far beyond any realistic rapid-migration
/// regime. The window costs `T + K + 1` route-table entries per session per inbound
/// direction (bounded by `MAX_ROUTES`, sized to preserve the session capacity).
pub const CID_WINDOW_TRAILING: u64 = 2;
/// See [`CID_WINDOW_TRAILING`].
pub const CID_WINDOW_LEADING: u64 = 16;

/// Per-direction, **session-stable** rotating-CID chain secrets. `outbound_secret`
/// is the chain this peer stamps its outbound `ConnId` from (the peer routes on
/// it); `inbound_secret` is the chain this peer routes inbound `ConnId`s on.
/// Derived once from the initial session secret; zeroized on drop.
pub struct CidChain {
    outbound_secret: [u8; 32],
    inbound_secret: [u8; 32],
}

impl CidChain {
    /// Derive the per-direction CID-chain secrets from the initial session
    /// secret. `is_server` swaps outbound/inbound so one peer's outbound chain
    /// equals the other peer's inbound chain (mirrors `HeaderProtector::derive`).
    pub fn derive(initial_secret: &[u8; 32], is_server: bool) -> Self {
        let c2s = derive_key_32(CID_C2S_LABEL, initial_secret);
        let s2c = derive_key_32(CID_S2C_LABEL, initial_secret);
        // Client stamps c2s outbound (server routes c2s); server stamps s2c.
        let (outbound_secret, inbound_secret) = if is_server { (s2c, c2s) } else { (c2s, s2c) };
        Self {
            outbound_secret,
            inbound_secret,
        }
    }

    /// The CID this peer stamps on its outbound envelope at migration index `i`.
    #[inline]
    pub fn outbound_cid(&self, i: u64) -> [u8; CID_LEN] {
        cid_from_secret(&self.outbound_secret, i)
    }

    /// The CID this peer routes an inbound envelope on at migration index `i`.
    #[inline]
    pub fn inbound_cid(&self, i: u64) -> [u8; CID_LEN] {
        cid_from_secret(&self.inbound_secret, i)
    }

    /// The inbound demux window `[highest_seen − trailing, highest_seen +
    /// leading]` (saturating at index 0), each index paired with the CID it
    /// routes on. Pure — the stateful slide lives in the demux (P4).
    pub fn inbound_window(
        &self,
        highest_seen: u64,
        trailing: u64,
        leading: u64,
    ) -> impl Iterator<Item = (u64, [u8; CID_LEN])> + '_ {
        let lo = highest_seen.saturating_sub(trailing);
        let hi = highest_seen.saturating_add(leading);
        (lo..=hi).map(move |i| (i, self.inbound_cid(i)))
    }
}

impl Drop for CidChain {
    fn drop(&mut self) {
        self.outbound_secret.zeroize();
        self.inbound_secret.zeroize();
    }
}

/// `CID_i = derive_key_32("phantom-cid-v1", secret ‖ i.to_be_bytes())[0..8]`.
#[inline]
fn cid_from_secret(secret: &[u8; 32], i: u64) -> [u8; CID_LEN] {
    let mut ikm = [0u8; 40];
    ikm[..32].copy_from_slice(secret);
    ikm[32..].copy_from_slice(&i.to_be_bytes());
    let full = derive_key_32(CID_LABEL, &ikm);
    let mut cid = [0u8; CID_LEN];
    cid.copy_from_slice(&full[..CID_LEN]);
    cid
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::crypto::kdf::derive_key_32;

    /// Independent reference for the CID construction — the "known construction"
    /// KAT. Locks the spec: label `phantom-cid-v1`, IKM = `secret ‖ index_be`,
    /// truncated to the first 8 bytes. Backend-agnostic (same `derive_key_32`
    /// dispatch), so it pins the construction on both the blake3 default and the
    /// HKDF-SHA256 fips build.
    fn reference_cid(secret: &[u8; 32], i: u64) -> [u8; 8] {
        let mut ikm = [0u8; 40];
        ikm[..32].copy_from_slice(secret);
        ikm[32..].copy_from_slice(&i.to_be_bytes());
        let full = derive_key_32("phantom-cid-v1", &ikm);
        let mut cid = [0u8; 8];
        cid.copy_from_slice(&full[..8]);
        cid
    }

    /// The per-direction secret a peer derives from the initial session secret.
    fn direction_secret(initial: &[u8; 32], c2s: bool) -> [u8; 32] {
        derive_key_32(
            if c2s {
                "phantom-cid-c2s-v1"
            } else {
                "phantom-cid-s2c-v1"
            },
            initial,
        )
    }

    /// KAT: each side's outbound chain matches the reference construction over
    /// the secret it stamps from. Client stamps c2s; server stamps s2c.
    #[test]
    fn outbound_cid_matches_known_construction() {
        let initial = [0x42u8; 32];
        let client = CidChain::derive(&initial, false);
        let server = CidChain::derive(&initial, true);
        let c2s = direction_secret(&initial, true);
        let s2c = direction_secret(&initial, false);
        for i in [0u64, 1, 7, 1000] {
            assert_eq!(client.outbound_cid(i), reference_cid(&c2s, i));
            assert_eq!(server.outbound_cid(i), reference_cid(&s2c, i));
        }
    }

    /// The routing contract: one peer's outbound chain is the other peer's
    /// inbound chain. Client stamps c2s (the chain the server routes on); server
    /// stamps s2c (the chain the client routes on). Mirrors the AEAD/HP swap.
    #[test]
    fn per_direction_swap_links_peers() {
        let initial = [0x9cu8; 32];
        let client = CidChain::derive(&initial, false);
        let server = CidChain::derive(&initial, true);
        for i in [0u64, 1, 5, 42, 9999] {
            assert_eq!(
                client.outbound_cid(i),
                server.inbound_cid(i),
                "client outbound (c2s) must equal server inbound (c2s)"
            );
            assert_eq!(
                server.outbound_cid(i),
                client.inbound_cid(i),
                "server outbound (s2c) must equal client inbound (s2c)"
            );
        }
    }

    /// Within one peer the two directions use independent secrets, so the
    /// outbound and inbound CIDs for the same index differ.
    #[test]
    fn directions_differ_within_peer() {
        let chain = CidChain::derive(&[0x77u8; 32], false);
        for i in [0u64, 1, 100] {
            assert_ne!(chain.outbound_cid(i), chain.inbound_cid(i));
        }
    }

    /// Distinctness across the index: rotation yields independent-looking CIDs
    /// (no collisions across a long run — the unlinkability property).
    #[test]
    fn cids_are_distinct_across_index() {
        let chain = CidChain::derive(&[0x11u8; 32], false);
        let mut seen = HashSet::new();
        for i in 0..256u64 {
            assert!(seen.insert(chain.outbound_cid(i)), "collision at index {i}");
        }
        assert_eq!(seen.len(), 256);
    }

    /// Deterministic: two independent derivations from the same inputs produce
    /// byte-identical CIDs (client and server must agree).
    #[test]
    fn derivation_is_deterministic() {
        let initial = [0x5au8; 32];
        let a = CidChain::derive(&initial, false);
        let b = CidChain::derive(&initial, false);
        for i in [0u64, 3, 64] {
            assert_eq!(a.outbound_cid(i), b.outbound_cid(i));
            assert_eq!(a.inbound_cid(i), b.inbound_cid(i));
        }
    }

    /// The inbound demux window covers `[highest_seen − T, highest_seen + K]`,
    /// each entry paired with the CID that index routes on.
    #[test]
    fn inbound_window_covers_trailing_and_leading() {
        let chain = CidChain::derive(&[0x55u8; 32], true);
        let win: Vec<(u64, [u8; 8])> = chain.inbound_window(10, 2, 4).collect();
        let idxs: Vec<u64> = win.iter().map(|(i, _)| *i).collect();
        assert_eq!(idxs, vec![8, 9, 10, 11, 12, 13, 14]);
        for (i, cid) in win {
            assert_eq!(cid, chain.inbound_cid(i));
        }
    }

    /// The trailing edge saturates at index 0 (never underflows).
    #[test]
    fn inbound_window_saturates_at_zero() {
        let chain = CidChain::derive(&[0x55u8; 32], true);
        let idxs: Vec<u64> = chain.inbound_window(1, 2, 4).map(|(i, _)| i).collect();
        assert_eq!(idxs, vec![0, 1, 2, 3, 4, 5]);
    }

    /// The canonical window size is `T + K + 1 = 19` entries (K widened 4→16 for
    /// EPS-01 robustness; see [`CID_WINDOW_LEADING`]).
    #[test]
    fn canonical_window_size() {
        let chain = CidChain::derive(&[0x55u8; 32], false);
        let n = chain
            .inbound_window(100, CID_WINDOW_TRAILING, CID_WINDOW_LEADING)
            .count();
        assert_eq!(n, (CID_WINDOW_TRAILING + CID_WINDOW_LEADING + 1) as usize);
        assert_eq!(n, 19);
    }

    /// Frozen-byte KAT (default/blake3 build): pins the exact CID bytes so an
    /// accidental construction change or an upstream blake3 behavior shift is
    /// caught — mirroring the NIST/RFC vectors in `header_protection.rs`. The
    /// fips/HKDF path is covered by the backend-agnostic construction KAT
    /// (`outbound_cid_matches_known_construction`) plus `kdf::derive_key_32_fips_kat`.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn frozen_cid_bytes_default_build() {
        let client = CidChain::derive(&[0x42u8; 32], false);
        assert_eq!(
            client.outbound_cid(0),
            [102, 235, 212, 72, 93, 23, 250, 126]
        );
        assert_eq!(client.outbound_cid(1), [24, 107, 241, 72, 75, 55, 3, 167]);
    }
}
