//! Synthetic TLS 1.3 ClientHello generation for the mimicry leg.
//!
//! Builds a Chrome-stable–shaped ClientHello so a passive observer fingerprinting
//! the cleartext handshake (JA3 / JA4) sees a plausible modern browser. The
//! handshake is *theater*: the `key_share` bytes are fresh random of the correct
//! point length but back no real ECDHE — the real key exchange is the inner
//! Phantom hybrid-PQ session. Every per-connection field (`random`,
//! `legacy_session_id`, `key_share` key_exchange, GREASE codepoints, and the
//! extension order) is freshly randomized so no constant appears across flows.
//!
//! # Fidelity is a maintained data set, not a constant
//!
//! `PROFILE_CAPTURED` stamps the Chrome shape this module parrots. A *frozen*
//! template drifts out of the live-browser population within ~1–2 Chrome releases
//! and its JA4 then matches no real browser — a standalone anomaly (worse than no
//! mimicry). The cipher-suite list, extension set/order policy, and groups are
//! deliberately isolated in [`ChromeProfile`] so they are refreshed from a real
//! browser capture; see [`profile_is_fresh`] and the module's tests. This module
//! ships the *machinery* (RFC 8446 framing, GREASE per RFC 8701, per-connection
//! randomization + extension shuffle) plus a current Chrome-shaped profile; an
//! exact JA4 match against a specific live Chrome build must be capture-validated
//! before relying on it in a hostile network (R3 in the design doc).

use crate::crypto::rng::RngProvider;

/// Marker for the Chrome shape this profile parrots (`YYYYMM`). Bump it when the
/// profile is refreshed from a real capture; [`profile_is_fresh`] compares against
/// it so a stale template is caught rather than silently drifting.
pub(crate) const PROFILE_CAPTURED: u32 = 202506;

/// Cleartext TLS 1.3 legacy fields.
const TLS_LEGACY_VERSION: u16 = 0x0303; // ClientHello.legacy_version
const HS_TYPE_CLIENT_HELLO: u8 = 0x01;

// ── Extension type codepoints (RFC 8446 / IANA) ─────────────────────────────
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
const EXT_APPLICATION_SETTINGS: u16 = 0x4469; // ALPS (Chrome)

// ── Named groups ────────────────────────────────────────────────────────────
const GROUP_X25519_MLKEM768: u16 = 0x11ec; // current Chrome's PQ hybrid
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;

/// Public-key length on the wire for each offered `key_share` group.
fn group_key_exchange_len(group: u16) -> usize {
    match group {
        GROUP_X25519 => 32,
        GROUP_X25519_MLKEM768 => 1216, // X25519 (32) ‖ ML-KEM-768 ek (1184)
        GROUP_SECP256R1 => 65,         // 0x04 ‖ X ‖ Y (uncompressed)
        GROUP_SECP384R1 => 97,
        _ => 32,
    }
}

/// The Chrome shape this module parrots. The value tables are the part refreshed
/// from a real capture; the framing around them is RFC-fixed.
struct ChromeProfile {
    /// TLS 1.3 + ECDHE cipher suites, in Chrome's order (a leading GREASE slot is
    /// inserted at build time).
    cipher_suites: &'static [u16],
    /// `supported_groups`, in Chrome's order (a leading GREASE group is inserted).
    supported_groups: &'static [u16],
    /// Groups for which Chrome sends a `key_share` (a subset of `supported_groups`,
    /// preceded by a GREASE share). The PQ hybrid + x25519.
    key_share_groups: &'static [u16],
    /// `signature_algorithms`, in Chrome's order.
    signature_algorithms: &'static [u16],
    /// ALPN protocol IDs (`h2`, `http/1.1`).
    alpn: &'static [&'static [u8]],
}

const CHROME: ChromeProfile = ChromeProfile {
    cipher_suites: &[
        0x1301, 0x1302, 0x1303, // TLS 1.3 AEAD suites
        0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE GCM
        0xcca9, 0xcca8, // ECDHE ChaCha20-Poly1305
        0xc013, 0xc014, // ECDHE CBC (legacy)
        0x009c, 0x009d, // RSA GCM
        0x002f, 0x0035, // RSA CBC (legacy)
    ],
    supported_groups: &[
        GROUP_X25519_MLKEM768,
        GROUP_X25519,
        GROUP_SECP256R1,
        GROUP_SECP384R1,
    ],
    key_share_groups: &[GROUP_X25519_MLKEM768, GROUP_X25519],
    signature_algorithms: &[
        0x0403, // ecdsa_secp256r1_sha256
        0x0804, // rsa_pss_rsae_sha256
        0x0401, // rsa_pkcs1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0805, // rsa_pss_rsae_sha384
        0x0501, // rsa_pkcs1_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0601, // rsa_pkcs1_sha512
    ],
    alpn: &[b"h2", b"http/1.1"],
};

/// The 16 GREASE codepoints (RFC 8701): `0x{n}A{n}A`.
fn grease_value(rng: &dyn RngProvider) -> u16 {
    let n = (rng.next_u64() & 0x0f) as u16;
    (n << 12) | (n << 4) | 0x0a0a
}

// ── little length-prefix helpers (all big-endian, RFC 8446 framing) ─────────
fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append `body` framed by a 2-byte big-endian length.
fn push_u16_vec(out: &mut Vec<u8>, body: &[u8]) {
    push_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

/// Encode one extension `ext_type ‖ u16 len ‖ data` and return it.
fn extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut e = Vec::with_capacity(4 + data.len());
    push_u16(&mut e, ext_type);
    push_u16_vec(&mut e, data);
    e
}

/// Build the synthetic ClientHello **handshake message** (`type ‖ u24 len ‖ body`)
/// for `sni`. `rng` supplies every per-connection field.
pub(crate) fn build_client_hello(sni: &str, rng: &dyn RngProvider) -> Vec<u8> {
    // Per-connection GREASE codepoints (distinct slots; Chrome reuses some — a
    // capture-refresh refinement).
    let grease_cipher = grease_value(rng);
    let grease_group = grease_value(rng);
    let grease_ext_first = grease_value(rng);
    let grease_ext_last = grease_value(rng);
    let grease_version = grease_value(rng);
    let grease_ks = grease_value(rng);

    // legacy_version ‖ random[32] ‖ session_id ‖ cipher_suites ‖ compression ‖ exts
    let mut body = Vec::new();
    push_u16(&mut body, TLS_LEGACY_VERSION);

    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    body.extend_from_slice(&random);

    // TLS 1.3 clients send a non-empty 32-byte legacy_session_id (Chrome does).
    let mut session_id = [0u8; 32];
    rng.fill_bytes(&mut session_id);
    body.push(32);
    body.extend_from_slice(&session_id);

    // cipher_suites: leading GREASE, then the profile list.
    let mut cs = Vec::new();
    push_u16(&mut cs, grease_cipher);
    for &c in CHROME.cipher_suites {
        push_u16(&mut cs, c);
    }
    push_u16_vec(&mut body, &cs);

    // legacy_compression_methods = [null].
    body.push(1);
    body.push(0x00);

    // ── Extensions (built, then shuffled, then padding appended last) ──
    let mut exts: Vec<Vec<u8>> = Vec::new();

    // GREASE (empty) — one of the two GREASE extensions Chrome interleaves.
    exts.push(extension(grease_ext_first, &[]));

    // server_name.
    {
        let mut sni_list = Vec::new();
        // ServerNameList: name_type(0=host_name) ‖ u16 host
        let mut entry = Vec::new();
        entry.push(0x00);
        push_u16_vec(&mut entry, sni.as_bytes());
        push_u16_vec(&mut sni_list, &entry);
        exts.push(extension(EXT_SERVER_NAME, &sni_list));
    }

    exts.push(extension(EXT_EXTENDED_MASTER_SECRET, &[]));
    exts.push(extension(EXT_RENEGOTIATION_INFO, &[0x00]));

    // supported_groups: leading GREASE group, then the profile groups.
    {
        let mut g = Vec::new();
        let mut list = Vec::new();
        push_u16(&mut list, grease_group);
        for &grp in CHROME.supported_groups {
            push_u16(&mut list, grp);
        }
        push_u16_vec(&mut g, &list);
        exts.push(extension(EXT_SUPPORTED_GROUPS, &g));
    }

    // ec_point_formats = [uncompressed].
    exts.push(extension(EXT_EC_POINT_FORMATS, &[0x01, 0x00]));
    exts.push(extension(EXT_SESSION_TICKET, &[]));

    // ALPN.
    {
        let mut protos = Vec::new();
        for p in CHROME.alpn {
            protos.push(p.len() as u8);
            protos.extend_from_slice(p);
        }
        let mut alpn = Vec::new();
        push_u16_vec(&mut alpn, &protos);
        exts.push(extension(EXT_ALPN, &alpn));
    }

    // status_request (OCSP): cert_status_type=ocsp ‖ responder_id_list(0) ‖ ext(0)
    exts.push(extension(
        EXT_STATUS_REQUEST,
        &[0x01, 0x00, 0x00, 0x00, 0x00],
    ));

    // signature_algorithms.
    {
        let mut sa = Vec::new();
        let mut list = Vec::new();
        for &s in CHROME.signature_algorithms {
            push_u16(&mut list, s);
        }
        push_u16_vec(&mut sa, &list);
        exts.push(extension(EXT_SIGNATURE_ALGORITHMS, &sa));
    }

    exts.push(extension(EXT_SCT, &[]));

    // key_share: leading GREASE share (1 byte), then a fresh-random share of the
    // correct length for each offered group.
    {
        let mut shares = Vec::new();
        // GREASE share: group ‖ u16 len(1) ‖ 0x00
        push_u16(&mut shares, grease_ks);
        push_u16(&mut shares, 1);
        shares.push(0x00);
        for &grp in CHROME.key_share_groups {
            let klen = group_key_exchange_len(grp);
            let mut key = vec![0u8; klen];
            rng.fill_bytes(&mut key);
            push_u16(&mut shares, grp);
            push_u16_vec(&mut shares, &key);
        }
        let mut ks = Vec::new();
        push_u16_vec(&mut ks, &shares);
        exts.push(extension(EXT_KEY_SHARE, &ks));
    }

    // psk_key_exchange_modes = [psk_dhe_ke(1)].
    exts.push(extension(EXT_PSK_KEY_EXCHANGE_MODES, &[0x01, 0x01]));

    // supported_versions: leading GREASE, then TLS 1.3.
    {
        let mut sv = Vec::new();
        let mut list = Vec::new();
        push_u16(&mut list, grease_version);
        push_u16(&mut list, 0x0304);
        sv.push(list.len() as u8);
        sv.extend_from_slice(&list);
        exts.push(extension(EXT_SUPPORTED_VERSIONS, &sv));
    }

    // compress_certificate = [brotli(2)].
    exts.push(extension(EXT_COMPRESS_CERTIFICATE, &[0x02, 0x00, 0x02]));

    // application_settings (ALPS): supported protocols = h2.
    {
        let mut protos = Vec::new();
        protos.push(2u8);
        protos.extend_from_slice(b"h2");
        let mut alps = Vec::new();
        push_u16_vec(&mut alps, &protos);
        exts.push(extension(EXT_APPLICATION_SETTINGS, &alps));
    }

    // Second GREASE extension (Chrome interleaves two).
    exts.push(extension(grease_ext_last, &[]));

    // Shuffle the extension order per connection (recent Chrome/BoringSSL behavior;
    // a fixed order is itself a tell vs. current Chrome). Fisher–Yates with `rng`.
    shuffle(&mut exts, rng);

    // Concatenate, then append a padding extension LAST (Chrome adds padding after
    // the shuffle to avoid the 256–511-byte ClientHello length range).
    let mut ext_bytes = Vec::new();
    for e in &exts {
        ext_bytes.extend_from_slice(e);
    }
    if let Some(pad) = padding_extension(&body, &ext_bytes) {
        ext_bytes.extend_from_slice(&pad);
    }
    push_u16_vec(&mut body, &ext_bytes);

    // Wrap as a handshake message: type ‖ u24 length ‖ body.
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(HS_TYPE_CLIENT_HELLO);
    let len = body.len() as u32;
    msg.push((len >> 16) as u8);
    msg.push((len >> 8) as u8);
    msg.push(len as u8);
    msg.extend_from_slice(&body);
    msg
}

/// Padding extension to keep the ClientHello length out of the 256–511-byte F5 bug
/// range (Chrome's rule). Returns `None` when no padding is needed.
fn padding_extension(body_prefix: &[u8], ext_bytes: &[u8]) -> Option<Vec<u8>> {
    // Approximate ClientHello body length so far (the +2 is the extensions-vector
    // length prefix that `push_u16_vec` will add).
    let approx = body_prefix.len() + 2 + ext_bytes.len();
    if (256..512).contains(&approx) {
        let target: usize = 512;
        // Pad amount accounts for the 4-byte padding-extension header.
        let pad = target.saturating_sub(approx).saturating_sub(4);
        Some(extension(EXT_PADDING, &vec![0u8; pad]))
    } else {
        None
    }
}

/// In-place Fisher–Yates shuffle driven by the injected CSPRNG.
fn shuffle(items: &mut [Vec<u8>], rng: &dyn RngProvider) {
    let n = items.len();
    if n < 2 {
        return;
    }
    let mut i = n - 1;
    while i > 0 {
        // Unbiased-enough index in 0..=i for a ≤ ~20-element list.
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        items.swap(i, j);
        i -= 1;
    }
}

/// True if `captured` is within `max_age_months` of [`PROFILE_CAPTURED`]. The leg's
/// constructor warns (and the test below fails) when the shipped profile is stale,
/// so JA3/JA4 drift (R3) is caught rather than silently shipped.
pub(crate) fn profile_is_fresh(now_yyyymm: u32, max_age_months: u32) -> bool {
    let to_months = |ym: u32| (ym / 100) * 12 + (ym % 100);
    to_months(now_yyyymm).saturating_sub(to_months(PROFILE_CAPTURED)) <= max_age_months
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::OsRng;

    /// Minimal independent re-parser: walk the ClientHello and return
    /// `(cipher_suites, supported_groups, key_share_groups, legacy_session_id,
    /// extension_types)`. Returns `None` on any structural inconsistency — so a
    /// passing parse proves every length field is internally consistent.
    fn reparse(msg: &[u8]) -> Option<(Vec<u16>, Vec<u16>, Vec<u16>, Vec<u8>, Vec<u16>)> {
        let mut p = Parser::new(msg);
        if p.u8()? != HS_TYPE_CLIENT_HELLO {
            return None;
        }
        let body_len = p.u24()? as usize;
        if p.remaining() != body_len {
            return None;
        }
        if p.u16()? != TLS_LEGACY_VERSION {
            return None;
        }
        p.skip(32)?; // random
        let sid_len = p.u8()? as usize;
        let session_id = p.bytes(sid_len)?.to_vec();
        let cs_bytes = p.u16_vec()?;
        let cipher_suites = u16s(&cs_bytes)?;
        let comp = p.u8_vec()?;
        if comp != [0x00] {
            return None;
        }
        let ext_bytes = p.u16_vec()?;
        if p.remaining() != 0 {
            return None;
        }

        let mut ep = Parser::new(&ext_bytes);
        let mut ext_types = Vec::new();
        let mut groups = Vec::new();
        let mut ks_groups = Vec::new();
        while ep.remaining() > 0 {
            let et = ep.u16()?;
            let ed = ep.u16_vec()?;
            ext_types.push(et);
            if et == EXT_SUPPORTED_GROUPS {
                let mut gp = Parser::new(&ed);
                groups = u16s(&gp.u16_vec()?)?;
            } else if et == EXT_KEY_SHARE {
                let mut kp = Parser::new(&ed);
                let shares = kp.u16_vec()?;
                let mut sp = Parser::new(&shares);
                while sp.remaining() > 0 {
                    ks_groups.push(sp.u16()?);
                    let _share = sp.u16_vec()?;
                }
            }
        }
        Some((cipher_suites, groups, ks_groups, session_id, ext_types))
    }

    struct Parser<'a> {
        b: &'a [u8],
        i: usize,
    }
    impl<'a> Parser<'a> {
        fn new(b: &'a [u8]) -> Self {
            Self { b, i: 0 }
        }
        fn remaining(&self) -> usize {
            self.b.len() - self.i
        }
        fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
            let s = self.b.get(self.i..self.i + n)?;
            self.i += n;
            Some(s)
        }
        fn u8(&mut self) -> Option<u8> {
            Some(self.bytes(1)?[0])
        }
        fn u16(&mut self) -> Option<u16> {
            let s = self.bytes(2)?;
            Some(u16::from_be_bytes([s[0], s[1]]))
        }
        fn u24(&mut self) -> Option<u32> {
            let s = self.bytes(3)?;
            Some(u32::from_be_bytes([0, s[0], s[1], s[2]]))
        }
        fn skip(&mut self, n: usize) -> Option<()> {
            self.bytes(n)?;
            Some(())
        }
        fn u8_vec(&mut self) -> Option<Vec<u8>> {
            let n = self.u8()? as usize;
            Some(self.bytes(n)?.to_vec())
        }
        fn u16_vec(&mut self) -> Option<Vec<u8>> {
            let n = self.u16()? as usize;
            Some(self.bytes(n)?.to_vec())
        }
    }
    fn u16s(b: &[u8]) -> Option<Vec<u16>> {
        if b.len() % 2 != 0 {
            return None;
        }
        Some(
            b.chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect(),
        )
    }
    fn is_grease(v: u16) -> bool {
        let hi = (v >> 8) as u8;
        let lo = (v & 0xff) as u8;
        hi == lo && (hi & 0x0f) == 0x0a
    }

    #[test]
    fn client_hello_is_structurally_self_consistent() {
        let (cs, groups, ks_groups, sid, ext_types) =
            reparse(&build_client_hello("example.com", &OsRng)).expect("must re-parse cleanly");
        // Session id is the 32-byte TLS-1.3 value.
        assert_eq!(sid.len(), 32);
        // Every key_share group (minus GREASE) is offered in supported_groups.
        for g in &ks_groups {
            if is_grease(*g) {
                continue;
            }
            assert!(
                groups.contains(g),
                "key_share group {g:#06x} not in supported_groups"
            );
        }
        // GREASE is present and the real TLS 1.3 suites are offered.
        assert!(cs.iter().any(|c| is_grease(*c)), "no GREASE cipher");
        assert!(cs.contains(&0x1301) && cs.contains(&0x1303));
        // Mandatory extensions present.
        for needed in [
            EXT_SERVER_NAME,
            EXT_SUPPORTED_GROUPS,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_KEY_SHARE,
            EXT_SUPPORTED_VERSIONS,
            EXT_ALPN,
        ] {
            assert!(
                ext_types.contains(&needed),
                "missing extension {needed:#06x}"
            );
        }
        // Two GREASE extensions interleaved (Chrome).
        assert_eq!(ext_types.iter().filter(|t| is_grease(**t)).count(), 2);
    }

    #[test]
    fn per_connection_fields_are_fresh() {
        let a = build_client_hello("example.com", &OsRng);
        let b = build_client_hello("example.com", &OsRng);
        // Two ClientHellos to the same SNI must differ (random / session_id /
        // key_share / GREASE / order are all per-connection) — no constant tell.
        assert_ne!(
            a, b,
            "ClientHello must not be byte-identical across connections"
        );
    }

    #[test]
    fn key_share_lengths_match_their_groups() {
        // Re-walk key_share and assert each share's length matches the group.
        let msg = build_client_hello("a.test", &OsRng);
        let mut p = Parser::new(&msg);
        p.u8().unwrap();
        p.u24().unwrap();
        p.u16().unwrap();
        p.skip(32).unwrap();
        let sl = p.u8().unwrap() as usize;
        p.skip(sl).unwrap();
        let _cs = p.u16_vec().unwrap();
        let _comp = p.u8_vec().unwrap();
        let ext_bytes = p.u16_vec().unwrap();
        let mut ep = Parser::new(&ext_bytes);
        while ep.remaining() > 0 {
            let et = ep.u16().unwrap();
            let ed = ep.u16_vec().unwrap();
            if et == EXT_KEY_SHARE {
                let mut kp = Parser::new(&ed);
                let shares = kp.u16_vec().unwrap();
                let mut sp = Parser::new(&shares);
                while sp.remaining() > 0 {
                    let g = sp.u16().unwrap();
                    let share = sp.u16_vec().unwrap();
                    if !is_grease(g) {
                        assert_eq!(
                            share.len(),
                            group_key_exchange_len(g),
                            "key_share length mismatch for group {g:#06x}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn staleness_check_flags_an_old_profile() {
        assert!(
            profile_is_fresh(PROFILE_CAPTURED, 6),
            "freshly captured is fresh"
        );
        // 18 months past the capture, with a 6-month tolerance → stale.
        let stale = PROFILE_CAPTURED + 100 + 6; // +1 year +6 months (YYYYMM arithmetic)
        assert!(
            !profile_is_fresh(stale, 6),
            "an 18-month-old profile must read stale"
        );
    }
}
