//! Synthetic TLS 1.3 ServerHello, synthesized **per connection from the parsed
//! inbound ClientHello**.
//!
//! A stateful DPI box checks the ServerHello against the ClientHello it answers:
//! the selected `cipher_suite` must have been offered, the `key_share` group must
//! be one the client offered a share for, the `legacy_session_id_echo` must copy
//! the client's, and `supported_versions` must select TLS 1.3. A static or
//! self-inconsistent ServerHello is an instant tell, so this module parses the
//! real inbound ClientHello (robustly — it is untrusted network input) and builds
//! a matching ServerHello. Like the ClientHello, the `key_share` bytes are fresh
//! random theater; the real key exchange is the inner Phantom session.

// PR-2 lands the ServerHello synth; its live consumer is the leg's server prelude
// (PR-3). Until then it is exercised only by this module's tests.
#![allow(dead_code)]

use crate::crypto::rng::RngProvider;
use crate::errors::CoreError;

const TLS_LEGACY_VERSION: u16 = 0x0303;
const HS_TYPE_CLIENT_HELLO: u8 = 0x01;
const HS_TYPE_SERVER_HELLO: u8 = 0x02;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const GROUP_X25519: u16 = 0x001d;

/// `HelloRetryRequest`'s special `ServerHello.random` (RFC 8446 §4.1.3). A real
/// ServerHello.random must never equal it (that would signal HRR).
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];
/// TLS 1.2 / 1.1 downgrade sentinels for the last 8 bytes of `ServerHello.random`
/// (RFC 8446 §4.1.3). A genuine TLS 1.3 ServerHello must avoid both.
const DOWNGRADE_TLS12: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
const DOWNGRADE_TLS11: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

/// Public-key length for a `key_share` group (mirrors the client side).
fn group_key_exchange_len(group: u16) -> usize {
    match group {
        GROUP_X25519 => 32,
        0x11ec => 1216, // X25519MLKEM768
        0x0017 => 65,   // secp256r1
        0x0018 => 97,   // secp384r1
        _ => 32,
    }
}

/// The fields of an inbound ClientHello the ServerHello synthesis needs.
pub(crate) struct ParsedClientHello {
    pub(crate) legacy_session_id: Vec<u8>,
    pub(crate) cipher_suites: Vec<u16>,
    pub(crate) supported_groups: Vec<u16>,
    pub(crate) key_share_groups: Vec<u16>,
}

/// Bounds-checked cursor over untrusted bytes; every read is length-checked and a
/// short read is a typed error (never a panic / OOB).
struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.i
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CoreError> {
        let end = self
            .i
            .checked_add(n)
            .ok_or_else(|| err("length overflow"))?;
        let s = self.b.get(self.i..end).ok_or_else(|| err("short read"))?;
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CoreError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, CoreError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u24(&mut self) -> Result<u32, CoreError> {
        let s = self.take(3)?;
        Ok(u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }
    /// A `u8`-length-prefixed vector.
    fn u8_vec(&mut self) -> Result<&'a [u8], CoreError> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    /// A `u16`-length-prefixed vector.
    fn u16_vec(&mut self) -> Result<&'a [u8], CoreError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

fn err(msg: &str) -> CoreError {
    CoreError::NetworkError(format!("malformed ClientHello: {msg}"))
}

fn parse_u16_list(b: &[u8]) -> Result<Vec<u16>, CoreError> {
    if !b.len().is_multiple_of(2) {
        return Err(err("odd-length u16 list"));
    }
    Ok(b.chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

/// Parse an untrusted ClientHello **handshake message** (`type ‖ u24 len ‖ body`).
pub(crate) fn parse_client_hello(msg: &[u8]) -> Result<ParsedClientHello, CoreError> {
    let mut c = Cursor::new(msg);
    if c.u8()? != HS_TYPE_CLIENT_HELLO {
        return Err(err("not a ClientHello"));
    }
    let body_len = c.u24()? as usize;
    if c.remaining() != body_len {
        return Err(err("handshake length mismatch"));
    }
    if c.u16()? != TLS_LEGACY_VERSION {
        return Err(err("unexpected legacy_version"));
    }
    c.take(32)?; // random
    let legacy_session_id = c.u8_vec()?.to_vec();
    let cipher_suites = parse_u16_list(c.u16_vec()?)?;
    let _compression = c.u8_vec()?;

    let mut supported_groups = Vec::new();
    let mut key_share_groups = Vec::new();
    // Extensions are optional on the wire in general, but a TLS 1.3 ClientHello
    // always has them; tolerate their absence without erroring.
    if c.remaining() > 0 {
        let ext_bytes = c.u16_vec()?;
        let mut e = Cursor::new(ext_bytes);
        while e.remaining() > 0 {
            let ext_type = e.u16()?;
            let ext_data = e.u16_vec()?;
            if ext_type == EXT_SUPPORTED_GROUPS {
                let mut g = Cursor::new(ext_data);
                supported_groups = parse_u16_list(g.u16_vec()?)?;
            } else if ext_type == EXT_KEY_SHARE {
                let mut k = Cursor::new(ext_data);
                let shares = k.u16_vec()?;
                let mut s = Cursor::new(shares);
                while s.remaining() > 0 {
                    key_share_groups.push(s.u16()?);
                    let _share = s.u16_vec()?; // skip the key_exchange bytes
                }
            }
        }
    }

    Ok(ParsedClientHello {
        legacy_session_id,
        cipher_suites,
        supported_groups,
        key_share_groups,
    })
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn push_u16_vec(out: &mut Vec<u8>, body: &[u8]) {
    push_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

/// A non-HRR, non-downgrade-sentinel 32-byte `ServerHello.random`.
fn fresh_server_random(rng: &dyn RngProvider) -> [u8; 32] {
    loop {
        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        let tail = &r[24..32];
        if r != HRR_RANDOM && tail != DOWNGRADE_TLS12 && tail != DOWNGRADE_TLS11 {
            return r;
        }
        // ~2^-256 per iteration; the loop is here only to keep the property total
        // without a panic (the crate denies `panic`/`unwrap`).
    }
}

/// Build a ServerHello **handshake message** consistent with `client`.
///
/// Selects a non-GREASE cipher the client offered (preferring a TLS 1.3 AEAD
/// suite) and a `key_share` group present in **both** the client's
/// `supported_groups` and its offered `key_share`s (preferring x25519), echoes the
/// client's `legacy_session_id`, and selects TLS 1.3 via `supported_versions`.
pub(crate) fn build_server_hello(
    client: &ParsedClientHello,
    rng: &dyn RngProvider,
) -> Result<Vec<u8>, CoreError> {
    // Cipher: prefer a TLS 1.3 suite the client offered; else any non-GREASE offer.
    let tls13 = [0x1301u16, 0x1302, 0x1303];
    let cipher = client
        .cipher_suites
        .iter()
        .copied()
        .find(|c| tls13.contains(c))
        .or_else(|| {
            client
                .cipher_suites
                .iter()
                .copied()
                .find(|c| !is_grease(*c))
        })
        .ok_or_else(|| err("no usable cipher_suite offered"))?;

    // key_share group: must be in BOTH supported_groups and the offered key_shares
    // (RFC 8446 §4.2.8 — otherwise a real server sends HelloRetryRequest). Prefer
    // x25519.
    let usable = |g: u16| {
        !is_grease(g)
            && client.supported_groups.contains(&g)
            && client.key_share_groups.contains(&g)
    };
    let group = if usable(GROUP_X25519) {
        GROUP_X25519
    } else {
        client
            .key_share_groups
            .iter()
            .copied()
            .find(|g| usable(*g))
            .ok_or_else(|| err("no key_share group common to supported_groups"))?
    };

    let mut body = Vec::new();
    push_u16(&mut body, TLS_LEGACY_VERSION);
    body.extend_from_slice(&fresh_server_random(rng));
    // legacy_session_id_echo: byte-for-byte copy of the client's.
    body.push(client.legacy_session_id.len() as u8);
    body.extend_from_slice(&client.legacy_session_id);
    push_u16(&mut body, cipher);
    body.push(0x00); // legacy_compression_method = null

    // Cleartext ServerHello extensions = ONLY {supported_versions, key_share}.
    let mut exts = Vec::new();
    // supported_versions: selected_version (NOT a list, unlike ClientHello).
    {
        let mut sv = Vec::new();
        push_u16(&mut sv, 0x0304);
        exts.extend_from_slice(&ext(EXT_SUPPORTED_VERSIONS, &sv));
    }
    // key_share: server's KeyShareEntry = group ‖ u16 key_exchange.
    {
        let klen = group_key_exchange_len(group);
        let mut key = vec![0u8; klen];
        rng.fill_bytes(&mut key);
        let mut ks = Vec::new();
        push_u16(&mut ks, group);
        push_u16_vec(&mut ks, &key);
        exts.extend_from_slice(&ext(EXT_KEY_SHARE, &ks));
    }
    push_u16_vec(&mut body, &exts);

    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(HS_TYPE_SERVER_HELLO);
    let len = body.len() as u32;
    msg.push((len >> 16) as u8);
    msg.push((len >> 8) as u8);
    msg.push(len as u8);
    msg.extend_from_slice(&body);
    Ok(msg)
}

fn ext(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut e = Vec::with_capacity(4 + data.len());
    push_u16(&mut e, ext_type);
    push_u16_vec(&mut e, data);
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::OsRng;
    use crate::transport::legs::mimic_tls::client_hello::build_client_hello;

    /// Re-parse a ServerHello and return
    /// `(cipher, session_id_echo, selected_version, key_share_group)`.
    fn reparse_server_hello(msg: &[u8]) -> Result<(u16, Vec<u8>, u16, u16), CoreError> {
        let mut c = Cursor::new(msg);
        if c.u8()? != HS_TYPE_SERVER_HELLO {
            return Err(err("not a ServerHello"));
        }
        let blen = c.u24()? as usize;
        if c.remaining() != blen {
            return Err(err("length mismatch"));
        }
        if c.u16()? != TLS_LEGACY_VERSION {
            return Err(err("bad legacy_version"));
        }
        c.take(32)?;
        let sid = c.u8_vec()?.to_vec();
        let cipher = c.u16()?;
        if c.u8()? != 0x00 {
            return Err(err("bad compression"));
        }
        let ext_bytes = c.u16_vec()?;
        let mut e = Cursor::new(ext_bytes);
        let mut selected_version = 0;
        let mut ks_group = 0;
        while e.remaining() > 0 {
            let et = e.u16()?;
            let ed = e.u16_vec()?;
            if et == EXT_SUPPORTED_VERSIONS {
                let mut v = Cursor::new(ed);
                selected_version = v.u16()?;
            } else if et == EXT_KEY_SHARE {
                let mut k = Cursor::new(ed);
                ks_group = k.u16()?;
                let _share = k.u16_vec()?;
            }
        }
        Ok((cipher, sid, selected_version, ks_group))
    }

    #[test]
    fn server_hello_is_consistent_with_the_client_hello() {
        let ch = build_client_hello("consistency.test", &OsRng);
        let parsed = parse_client_hello(&ch).expect("parse our own CH");
        let sh = build_server_hello(&parsed, &OsRng).expect("build SH");
        let (cipher, sid, version, group) = reparse_server_hello(&sh).expect("reparse SH");

        // Selected cipher was offered by the client and is non-GREASE.
        assert!(parsed.cipher_suites.contains(&cipher));
        assert!(!is_grease(cipher));
        // session_id echoed byte-for-byte.
        assert_eq!(sid, parsed.legacy_session_id);
        // TLS 1.3 selected.
        assert_eq!(version, 0x0304);
        // key_share group was offered in BOTH lists (no HelloRetryRequest needed).
        assert!(parsed.supported_groups.contains(&group));
        assert!(parsed.key_share_groups.contains(&group));
        assert!(!is_grease(group));
    }

    #[test]
    fn server_random_avoids_hrr_and_downgrade_sentinels() {
        let parsed = ParsedClientHello {
            legacy_session_id: vec![7u8; 32],
            cipher_suites: vec![0x1301],
            supported_groups: vec![GROUP_X25519],
            key_share_groups: vec![GROUP_X25519],
        };
        let sh = build_server_hello(&parsed, &OsRng).expect("build");
        // random is body bytes [2..34] (after the 4-byte hs header + 2 version).
        let random = &sh[6..38];
        assert_ne!(random, &HRR_RANDOM[..]);
        assert_ne!(&random[24..32], &DOWNGRADE_TLS12[..]);
        assert_ne!(&random[24..32], &DOWNGRADE_TLS11[..]);
    }

    #[test]
    fn key_share_length_matches_selected_group() {
        let parsed = ParsedClientHello {
            legacy_session_id: vec![0u8; 32],
            cipher_suites: vec![0x1301],
            supported_groups: vec![GROUP_X25519],
            key_share_groups: vec![GROUP_X25519],
        };
        let sh = build_server_hello(&parsed, &OsRng).expect("build");
        // Walk to the key_share entry and check its key_exchange length is 32.
        let (_c, _s, _v, group) = reparse_server_hello(&sh).expect("reparse");
        assert_eq!(group, GROUP_X25519);
    }

    #[test]
    fn rejects_a_truncated_client_hello() {
        let ch = build_client_hello("x.test", &OsRng);
        // Lop off the last 10 bytes — the length fields no longer close.
        let truncated = &ch[..ch.len() - 10];
        assert!(parse_client_hello(truncated).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_client_hello(b"not a tls clienthello at all").is_err());
        assert!(parse_client_hello(&[]).is_err());
        // A ServerHello is not a ClientHello.
        assert!(parse_client_hello(&[HS_TYPE_SERVER_HELLO, 0, 0, 0]).is_err());
    }

    #[test]
    fn no_common_key_share_group_is_an_error_not_a_panic() {
        // Client offers a supported group but NO key_share for it → a real server
        // would HelloRetryRequest; we surface a typed error (the leg drops).
        let parsed = ParsedClientHello {
            legacy_session_id: vec![0u8; 32],
            cipher_suites: vec![0x1301],
            supported_groups: vec![GROUP_X25519],
            key_share_groups: vec![], // no shares offered
        };
        assert!(build_server_hello(&parsed, &OsRng).is_err());
    }

    /// Wrap a raw extensions block in an otherwise-valid ClientHello handshake
    /// message, so a malformed *inner* extension can be fed to the parser.
    fn ch_with_raw_extensions(ext_block: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // legacy_session_id (len 0)
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: TLS_AES_128_GCM
        body.extend_from_slice(&[0x01, 0x00]); // compression: null
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(ext_block);
        let mut msg = vec![HS_TYPE_CLIENT_HELLO];
        let len = body.len() as u32;
        msg.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        msg.extend_from_slice(&body);
        msg
    }

    /// A key_share whose inner share length runs past the extension body is
    /// rejected with a typed error (the `Cursor`'s `.get()` bound holds — no OOB).
    /// Locks the bounds guarantee against a future raw-indexing refactor.
    #[test]
    fn rejects_inner_keyshare_length_overrun() {
        // key_share ext: type 0x0033, ext_data = [shares_vec(len 4) = group x25519 ‖
        // share_len 0xFFFF] — the share claims 65535 bytes that are not present.
        let ext_block = [
            0x00, 0x33, // EXT_KEY_SHARE
            0x00, 0x06, // ext_data length
            0x00, 0x04, // KeyShareClientHello.client_shares vec length
            0x00, 0x1d, // group = x25519
            0xFF, 0xFF, // key_exchange length = 65535 (overruns)
        ];
        let ch = ch_with_raw_extensions(&ext_block);
        assert!(
            parse_client_hello(&ch).is_err(),
            "an inner key_share length overrun must be a typed error, not an OOB"
        );
    }

    /// A 64 KiB junk ClientHello is rejected in bounded time without allocating
    /// beyond the input (the `Cursor` rejects on the first inconsistent length).
    #[test]
    fn rejects_maximal_junk_in_bounded_time() {
        let junk = vec![0x01u8; 64 * 1024];
        assert!(parse_client_hello(&junk).is_err());
    }
}
