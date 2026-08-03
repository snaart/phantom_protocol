//! The raw server → client UDP capacity control: wire format and bookkeeping.
//!
//! ## Why it exists
//!
//! Every leg's `download` number is a statement about the receive direction,
//! and without a control in that direction none of them can be attributed. In
//! one run every leg — including the mature reference implementation — landed
//! between 1.7 and 3.7 Mbit/s downstream while the client → server control
//! reported tens of megabits. Nothing in that artifact could distinguish "the
//! protocol is slow at receiving" from "the server's uplink is 3 Mbit/s", and
//! the two conclusions call for opposite work. This control is the denominator
//! that separates them.
//!
//! ## What it is
//!
//! The client asks the daemon to send at a rate for an interval; the daemon
//! paces raw datagrams at it and afterwards states, in its own words, how many
//! it actually managed. The client counts what arrived. There is no protocol
//! between them in the measured direction — no acknowledgement, no
//! retransmission, no congestion control, no encryption. Putting any of those
//! in would mean measuring them instead of the path.
//!
//! Each datagram is sequence-numbered, which is what turns "some bytes are
//! missing" into loss, reordering and duplication as separate quantities.
//!
//! ## The one thing that is not raw
//!
//! A bare "send me a flood" datagram is an amplifier: 40 bytes in, hundreds of
//! megabytes out, at whatever source address the sender cares to forge. So the
//! *request* carries a cookie the daemon minted for that exact peer address,
//! and a request without a valid one is answered with a 28-byte challenge
//! rather than a burst. This is return routability, not authentication: it
//! proves only that whoever asked can receive at the address they claim. It
//! adds one round trip before the first rung and touches nothing in the
//! measured direction — the burst itself is still raw datagrams on an
//! unconnected socket.

use std::net::{IpAddr, SocketAddr};

use phantom_protocol::crypto::kdf::derive_key_32;

// ── Message kinds ───────────────────────────────────────────────────────────
//
// Four fixed-layout datagrams, distinguished by an eight-byte magic. A magic
// rather than a one-byte tag because this listener sits on a public port and
// must be able to ignore stray traffic — a scan, a reflected packet, another
// tool's probe — without ever answering it.

pub const MAGIC_REQUEST: [u8; 8] = *b"PHRAWDQ1";
pub const MAGIC_CHALLENGE: [u8; 8] = *b"PHRAWDC1";
pub const MAGIC_DATA: [u8; 8] = *b"PHRAWDD1";
pub const MAGIC_REPORT: [u8; 8] = *b"PHRAWDR1";

pub const COOKIE_LEN: usize = 12;
pub const REQUEST_LEN: usize = 40;
pub const CHALLENGE_LEN: usize = 28;
/// Fixed prefix every data datagram carries; the rest is filler.
pub const DATA_HEADER_LEN: usize = 34;
pub const REPORT_LEN: usize = 46;

/// Smallest datagram that still carries a whole data header.
pub const MIN_PAYLOAD: usize = DATA_HEADER_LEN;

/// Largest datagram the control will send.
///
/// Under the path MTU this harness measures (~1420 B), so a rung is testing the
/// link's rate rather than its fragmentation behaviour — that question belongs
/// to the size sweep, which probes it deliberately.
pub const MAX_PAYLOAD: usize = 1400;

/// Datagram size the ladder uses unless told otherwise. Matches the client →
/// server control, so the two directions are counting the same shaped traffic.
pub const DEFAULT_PAYLOAD: usize = 1200;

// ── Request ─────────────────────────────────────────────────────────────────

/// Client → daemon: "send me `offered_kbps` for `duration_ms`".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// Distinguishes one probe run's traffic from another's on a shared port,
    /// so a burst outliving its requester cannot be counted into a later run.
    pub run_nonce: u64,
    /// All zeroes when the client has none yet, which asks for a challenge.
    pub cookie: [u8; COOKIE_LEN],
    pub rung: u16,
    pub offered_kbps: u32,
    pub duration_ms: u32,
    pub payload_len: u16,
}

impl Request {
    pub fn encode(&self) -> [u8; REQUEST_LEN] {
        let mut b = [0u8; REQUEST_LEN];
        b[0..8].copy_from_slice(&MAGIC_REQUEST);
        b[8..16].copy_from_slice(&self.run_nonce.to_be_bytes());
        b[16..28].copy_from_slice(&self.cookie);
        b[28..30].copy_from_slice(&self.rung.to_be_bytes());
        b[30..34].copy_from_slice(&self.offered_kbps.to_be_bytes());
        b[34..38].copy_from_slice(&self.duration_ms.to_be_bytes());
        b[38..40].copy_from_slice(&self.payload_len.to_be_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < REQUEST_LEN || b[0..8] != MAGIC_REQUEST {
            return None;
        }
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&b[16..28]);
        Some(Self {
            run_nonce: be64(&b[8..16]),
            cookie,
            rung: be16(&b[28..30]),
            offered_kbps: be32(&b[30..34]),
            duration_ms: be32(&b[34..38]),
            payload_len: be16(&b[38..40]),
        })
    }

    pub fn has_cookie(&self) -> bool {
        self.cookie != [0u8; COOKIE_LEN]
    }
}

// ── Challenge ───────────────────────────────────────────────────────────────

/// Daemon → client: "come back with this". Smaller than the request that
/// provoked it, so the unauthenticated path cannot be used to amplify anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge {
    pub run_nonce: u64,
    pub cookie: [u8; COOKIE_LEN],
}

impl Challenge {
    pub fn encode(&self) -> [u8; CHALLENGE_LEN] {
        let mut b = [0u8; CHALLENGE_LEN];
        b[0..8].copy_from_slice(&MAGIC_CHALLENGE);
        b[8..16].copy_from_slice(&self.run_nonce.to_be_bytes());
        b[16..28].copy_from_slice(&self.cookie);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < CHALLENGE_LEN || b[0..8] != MAGIC_CHALLENGE {
            return None;
        }
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&b[16..28]);
        Some(Self {
            run_nonce: be64(&b[8..16]),
            cookie,
        })
    }
}

// ── Data ────────────────────────────────────────────────────────────────────

/// The fixed prefix of one paced datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    pub run_nonce: u64,
    pub rung: u16,
    /// Zero-based within the rung, incremented once per datagram put on the
    /// socket. This is what makes loss, reordering and duplication separable
    /// quantities instead of one byte-count shortfall.
    pub seq: u64,
    pub send_unix_ns: u64,
}

impl DataHeader {
    /// Write the header into the front of an already-sized datagram buffer.
    ///
    /// In-place rather than allocating: the send loop runs at up to twenty
    /// thousand datagrams a second and a per-datagram allocation there would be
    /// the sender's own bottleneck, which is exactly the confound this control
    /// exists to rule out.
    pub fn write_into(&self, buf: &mut [u8]) {
        if buf.len() < DATA_HEADER_LEN {
            return;
        }
        buf[0..8].copy_from_slice(&MAGIC_DATA);
        buf[8..16].copy_from_slice(&self.run_nonce.to_be_bytes());
        buf[16..18].copy_from_slice(&self.rung.to_be_bytes());
        buf[18..26].copy_from_slice(&self.seq.to_be_bytes());
        buf[26..34].copy_from_slice(&self.send_unix_ns.to_be_bytes());
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < DATA_HEADER_LEN || b[0..8] != MAGIC_DATA {
            return None;
        }
        Some(Self {
            run_nonce: be64(&b[8..16]),
            rung: be16(&b[16..18]),
            seq: be64(&b[18..26]),
            send_unix_ns: be64(&b[26..34]),
        })
    }
}

// ── Report ──────────────────────────────────────────────────────────────────

/// Daemon → client, after the rung: what the sender actually achieved.
///
/// Without this the client can only compare arrivals against a rate that was
/// *asked for*, and a sender that never reached its own offer would be recorded
/// as a path that lost the difference. That mistake has already been made in
/// this project, in the other direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub run_nonce: u64,
    pub rung: u16,
    pub offered_kbps: u32,
    /// Datagrams the sender put on its own socket, not datagrams it intended.
    pub datagrams: u64,
    pub bytes: u64,
    /// The sender's own measurement of how long that took.
    pub elapsed_ns: u64,
}

impl Report {
    pub fn encode(&self) -> [u8; REPORT_LEN] {
        let mut b = [0u8; REPORT_LEN];
        b[0..8].copy_from_slice(&MAGIC_REPORT);
        b[8..16].copy_from_slice(&self.run_nonce.to_be_bytes());
        b[16..18].copy_from_slice(&self.rung.to_be_bytes());
        b[18..22].copy_from_slice(&self.offered_kbps.to_be_bytes());
        b[22..30].copy_from_slice(&self.datagrams.to_be_bytes());
        b[30..38].copy_from_slice(&self.bytes.to_be_bytes());
        b[38..46].copy_from_slice(&self.elapsed_ns.to_be_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < REPORT_LEN || b[0..8] != MAGIC_REPORT {
            return None;
        }
        Some(Self {
            run_nonce: be64(&b[8..16]),
            rung: be16(&b[16..18]),
            offered_kbps: be32(&b[18..22]),
            datagrams: be64(&b[22..30]),
            bytes: be64(&b[30..38]),
            elapsed_ns: be64(&b[38..46]),
        })
    }
}

// ── Return-routability cookie ───────────────────────────────────────────────

/// Seconds a cookie epoch covers. A cookie is accepted in its own epoch and the
/// previous one, so validity is between one and two minutes — long enough for a
/// whole ladder, short enough that a captured cookie is not a standing licence.
const EPOCH_SECS: u64 = 60;

/// Mints and checks the per-peer cookie that gates a burst.
///
/// Stateless by construction: nothing is remembered between datagrams. The
/// cookie is a keyed hash of the peer's address and the current epoch, so
/// verifying one is recomputing it — there is no table to grow and nothing an
/// attacker can fill.
pub struct CookieMinter {
    secret: [u8; 32],
}

impl Default for CookieMinter {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieMinter {
    /// A fresh secret per process. A restart invalidates outstanding cookies,
    /// which costs a client one extra round trip and costs an attacker the
    /// whole thing.
    pub fn new() -> Self {
        use phantom_protocol::crypto::rng::{OsRng, RngProvider};
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self { secret }
    }

    pub fn mint(&self, peer: SocketAddr, now_secs: u64) -> [u8; COOKIE_LEN] {
        self.mint_for_epoch(peer, now_secs / EPOCH_SECS)
    }

    /// True when `cookie` is one this minter issued to this peer, recently.
    pub fn verify(&self, cookie: &[u8], peer: SocketAddr, now_secs: u64) -> bool {
        if cookie.len() != COOKIE_LEN {
            return false;
        }
        let epoch = now_secs / EPOCH_SECS;
        // The previous epoch is accepted too, or a ladder that straddles a
        // minute boundary would be interrupted by a challenge mid-run.
        (0..=1).any(|back| {
            epoch
                .checked_sub(back)
                .is_some_and(|e| self.mint_for_epoch(peer, e) == cookie)
        })
    }

    fn mint_for_epoch(&self, peer: SocketAddr, epoch: u64) -> [u8; COOKIE_LEN] {
        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(&self.secret);
        match peer.ip() {
            IpAddr::V4(v4) => {
                ikm.push(4);
                ikm.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                ikm.push(6);
                ikm.extend_from_slice(&v6.octets());
            }
        }
        ikm.extend_from_slice(&peer.port().to_be_bytes());
        ikm.extend_from_slice(&epoch.to_be_bytes());

        let mac = derive_key_32("phantom-testbed-raw-downlink-cookie-v1", &ikm);
        let mut out = [0u8; COOKIE_LEN];
        out[0..4].copy_from_slice(&(epoch as u32).to_be_bytes());
        out[4..COOKIE_LEN].copy_from_slice(&mac[0..COOKIE_LEN - 4]);
        out
    }
}

// ── Receiver bookkeeping ────────────────────────────────────────────────────

/// Sequence numbers the duplicate bitmap can look back over.
///
/// Four thousand datagrams is roughly a fifth of a second at the top of the
/// ladder — far beyond any reordering a path plausibly produces, and a fixed
/// cost of 512 bytes whatever the rung's length. A bounded window rather than a
/// set of every sequence number seen, because the receive loop must not become
/// the thing that limits the measurement.
const WINDOW_BITS: usize = 4096;
const WINDOW_WORDS: usize = WINDOW_BITS / 64;

/// Counts arrivals, reordering and duplication from a stream of sequence
/// numbers.
///
/// Loss is deliberately *not* derived here from gaps: a gap at the receiver is
/// indistinguishable from a datagram the sender never sent, and the sender's
/// own count is the only honest denominator. See [`SeqTracker::loss_fraction`].
#[derive(Debug)]
pub struct SeqTracker {
    highest: Option<u64>,
    received: u64,
    duplicates: u64,
    reordered: u64,
    window: [u64; WINDOW_WORDS],
}

impl Default for SeqTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SeqTracker {
    pub fn new() -> Self {
        Self {
            highest: None,
            received: 0,
            duplicates: 0,
            reordered: 0,
            window: [0; WINDOW_WORDS],
        }
    }

    /// Record one arrival. Returns false when the datagram was a duplicate, so
    /// the caller can keep its byte count to distinct datagrams.
    pub fn observe(&mut self, seq: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(seq);
            self.mark(seq);
            self.received = 1;
            return true;
        };

        if seq > highest {
            self.slide_to(seq);
            self.highest = Some(seq);
            self.mark(seq);
            self.received += 1;
            return true;
        }

        // At or below the high-water mark: either a duplicate, or a datagram
        // overtaken in flight.
        let behind = highest - seq;
        if behind < WINDOW_BITS as u64 {
            if self.is_marked(seq) {
                self.duplicates += 1;
                return false;
            }
            self.mark(seq);
        }
        // Beyond the window it cannot be dup-checked; counting it as an arrival
        // is the conservative choice, since treating a real datagram as a
        // duplicate would understate what the path delivered.
        self.reordered += 1;
        self.received += 1;
        true
    }

    pub fn received(&self) -> u64 {
        self.received
    }

    pub fn duplicates(&self) -> u64 {
        self.duplicates
    }

    /// Datagrams that arrived after a higher-numbered one already had.
    pub fn reordered(&self) -> u64 {
        self.reordered
    }

    pub fn highest_seq(&self) -> Option<u64> {
        self.highest
    }

    /// The fraction of the sender's datagrams that never arrived.
    ///
    /// `None` when the sender's count is unknown — without it there is no
    /// denominator, and inventing one from the highest sequence number seen
    /// would silently report zero loss for a rung that was cut off early.
    pub fn loss_fraction(&self, sender_datagrams: Option<u64>) -> Option<f64> {
        let sent = sender_datagrams?;
        if sent == 0 {
            return None;
        }
        let ratio = self.received.min(sent) as f64 / sent as f64;
        Some((1.0 - ratio).clamp(0.0, 1.0))
    }

    fn slide_to(&mut self, seq: u64) {
        let Some(highest) = self.highest else { return };
        let advance = seq - highest;
        if advance >= WINDOW_BITS as u64 {
            self.window = [0; WINDOW_WORDS];
            return;
        }
        // The bitmap is addressed by sequence number modulo the window, so
        // advancing means clearing the slots newly swept into view.
        for s in (highest + 1)..=seq {
            self.clear(s);
        }
    }

    fn slot(seq: u64) -> (usize, u64) {
        let bit = (seq % WINDOW_BITS as u64) as usize;
        (bit / 64, 1u64 << (bit % 64))
    }

    fn mark(&mut self, seq: u64) {
        let (w, m) = Self::slot(seq);
        self.window[w] |= m;
    }

    fn clear(&mut self, seq: u64) {
        let (w, m) = Self::slot(seq);
        self.window[w] &= !m;
    }

    fn is_marked(&self, seq: u64) -> bool {
        let (w, m) = Self::slot(seq);
        self.window[w] & m != 0
    }
}

// ── Fixed-width readers ─────────────────────────────────────────────────────

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(s: &str) -> SocketAddr {
        s.parse().expect("test address")
    }

    #[test]
    fn every_datagram_round_trips() {
        let req = Request {
            run_nonce: 0xDEAD_BEEF_CAFE_1234,
            cookie: [7u8; COOKIE_LEN],
            rung: 3,
            offered_kbps: 60_000,
            duration_ms: 5_000,
            payload_len: 1200,
        };
        assert_eq!(Request::decode(&req.encode()), Some(req));

        let ch = Challenge {
            run_nonce: 9,
            cookie: [1u8; COOKIE_LEN],
        };
        assert_eq!(Challenge::decode(&ch.encode()), Some(ch));

        let dh = DataHeader {
            run_nonce: u64::MAX,
            rung: 4,
            seq: 123_456,
            send_unix_ns: 1_700_000_000_000_000_000,
        };
        let mut buf = vec![0u8; 1200];
        dh.write_into(&mut buf);
        assert_eq!(DataHeader::decode(&buf), Some(dh));

        let rep = Report {
            run_nonce: 5,
            rung: 2,
            offered_kbps: 20_000,
            datagrams: 104_000,
            bytes: 124_800_000,
            elapsed_ns: 5_000_000_000,
        };
        assert_eq!(Report::decode(&rep.encode()), Some(rep));
    }

    /// This listener sits on a public port. Anything it does not recognise must
    /// decode to `None` rather than being half-parsed — and, at the daemon, must
    /// draw no reply at all.
    #[test]
    fn foreign_and_truncated_datagrams_decode_to_nothing() {
        assert_eq!(Request::decode(&[]), None);
        assert_eq!(Request::decode(&[0u8; REQUEST_LEN]), None);
        assert_eq!(Request::decode(b"GET / HTTP/1.1\r\n"), None);
        // Right magic, one byte short.
        let short = &Request {
            run_nonce: 1,
            cookie: [0; COOKIE_LEN],
            rung: 0,
            offered_kbps: 1,
            duration_ms: 1,
            payload_len: 1200,
        }
        .encode()[..REQUEST_LEN - 1];
        assert_eq!(Request::decode(short), None);

        assert_eq!(Challenge::decode(&[0u8; CHALLENGE_LEN]), None);
        assert_eq!(DataHeader::decode(&[0u8; DATA_HEADER_LEN]), None);
        assert_eq!(Report::decode(&[0u8; REPORT_LEN]), None);
        // Each kind must reject the others' magic, so a reflected datagram is
        // never mistaken for a reply.
        let mut wrong_magic = vec![0u8; 128];
        wrong_magic[0..8].copy_from_slice(&MAGIC_DATA);
        assert_eq!(Report::decode(&wrong_magic), None);
        assert_eq!(Challenge::decode(&wrong_magic), None);
        wrong_magic[0..8].copy_from_slice(&MAGIC_REPORT);
        assert_eq!(DataHeader::decode(&wrong_magic), None);
        assert_eq!(Request::decode(&wrong_magic), None);
    }

    #[test]
    fn a_zero_cookie_asks_for_a_challenge() {
        let mut r = Request {
            run_nonce: 1,
            cookie: [0; COOKIE_LEN],
            rung: 0,
            offered_kbps: 1_000,
            duration_ms: 100,
            payload_len: 1200,
        };
        assert!(!r.has_cookie());
        r.cookie[3] = 1;
        assert!(r.has_cookie());
    }

    /// The property that stops the control being an open amplifier: a cookie is
    /// only good for the address it was minted for.
    #[test]
    fn a_cookie_is_bound_to_its_peer_and_its_epoch() {
        let m = CookieMinter::new();
        let a = peer("203.0.113.7:40000");
        let b = peer("198.51.100.9:40000");
        let now = 1_700_000_000u64;

        let c = m.mint(a, now);
        assert!(m.verify(&c, a, now));
        assert!(
            !m.verify(&c, b, now),
            "another address must not be able to use it"
        );
        assert!(
            !m.verify(&c, peer("203.0.113.7:40001"), now),
            "another port must not be able to use it"
        );
        assert!(
            m.verify(&c, a, now + EPOCH_SECS),
            "the next epoch still accepts it"
        );
        assert!(
            !m.verify(&c, a, now + 3 * EPOCH_SECS),
            "an old cookie must expire"
        );
        assert!(
            !m.verify(&[0u8; COOKIE_LEN], a, now),
            "a zero cookie is not valid"
        );
        assert!(!m.verify(&[], a, now), "a truncated cookie is not valid");

        // Two daemons must not accept each other's cookies.
        assert!(!CookieMinter::new().verify(&c, a, now));

        // IPv6 peers are covered by the same construction.
        let v6 = peer("[2001:db8::1]:4344");
        let c6 = m.mint(v6, now);
        assert!(m.verify(&c6, v6, now));
        assert!(!m.verify(&c6, a, now));
    }

    #[test]
    fn an_in_order_stream_shows_no_loss_no_reordering_and_no_duplication() {
        let mut t = SeqTracker::new();
        for seq in 0..10_000u64 {
            assert!(t.observe(seq));
        }
        assert_eq!(t.received(), 10_000);
        assert_eq!(t.reordered(), 0);
        assert_eq!(t.duplicates(), 0);
        assert_eq!(t.highest_seq(), Some(9_999));
        assert_eq!(t.loss_fraction(Some(10_000)), Some(0.0));
    }

    /// Loss is measured against what the sender says it sent, never against the
    /// highest sequence number that happened to arrive.
    #[test]
    fn loss_is_measured_against_the_senders_own_count() {
        let mut t = SeqTracker::new();
        for seq in 0..1000u64 {
            if seq % 10 != 0 {
                t.observe(seq);
            }
        }
        assert_eq!(t.received(), 900);
        let loss = t.loss_fraction(Some(1000)).expect("sender count known");
        assert!((loss - 0.10).abs() < 1e-9, "got {loss}");

        // A rung cut off after 400 datagrams loses 60% against the offer, and
        // that is only visible because the sender said how many it sent.
        let mut cut = SeqTracker::new();
        for seq in 0..400u64 {
            cut.observe(seq);
        }
        let loss = cut.loss_fraction(Some(1000)).expect("sender count known");
        assert!((loss - 0.60).abs() < 1e-9, "got {loss}");

        // Without the sender's count there is no denominator, and guessing one
        // would report this same rung as lossless.
        assert_eq!(cut.loss_fraction(None), None);
        assert_eq!(cut.loss_fraction(Some(0)), None);
    }

    #[test]
    fn reordering_is_counted_separately_from_loss() {
        let mut t = SeqTracker::new();
        // 0,1,3,2,4 — one datagram overtaken.
        for seq in [0u64, 1, 3, 2, 4] {
            assert!(t.observe(seq));
        }
        assert_eq!(t.received(), 5);
        assert_eq!(t.reordered(), 1);
        assert_eq!(t.duplicates(), 0);
        assert_eq!(t.loss_fraction(Some(5)), Some(0.0));
    }

    #[test]
    fn duplicates_are_counted_and_not_credited_as_arrivals() {
        let mut t = SeqTracker::new();
        for seq in 0..100u64 {
            t.observe(seq);
        }
        assert!(!t.observe(50), "a repeat must report itself as a duplicate");
        assert!(!t.observe(99));
        assert_eq!(t.duplicates(), 2);
        assert_eq!(t.received(), 100, "a duplicate is not a second arrival");
        assert_eq!(t.reordered(), 0, "nor is it a reordering");
        // And a duplicate must never make loss look negative.
        assert_eq!(t.loss_fraction(Some(100)), Some(0.0));
    }

    /// A datagram older than the window cannot be dup-checked. Counting it as
    /// an arrival understates duplication rather than overstating loss, which
    /// is the safer direction for a control.
    #[test]
    fn an_arrival_older_than_the_window_is_still_counted() {
        let mut t = SeqTracker::new();
        t.observe(0);
        t.observe(WINDOW_BITS as u64 * 2);
        assert!(t.observe(1));
        assert_eq!(t.received(), 3);
        assert_eq!(t.reordered(), 1);
    }

    /// A long stream must not accumulate false duplicates as the bitmap wraps.
    #[test]
    fn the_window_slides_without_leaving_stale_marks() {
        let mut t = SeqTracker::new();
        for seq in 0..(WINDOW_BITS as u64 * 5) {
            assert!(t.observe(seq), "seq {seq} was wrongly seen as a duplicate");
        }
        assert_eq!(t.duplicates(), 0);
        assert_eq!(t.received(), WINDOW_BITS as u64 * 5);

        // A jump past the window clears it wholesale; nothing behind the jump
        // may still read as marked.
        let far = WINDOW_BITS as u64 * 20;
        t.observe(far);
        assert!(t.observe(far - 1), "the swept region must be clear");
        assert_eq!(t.duplicates(), 0);
    }

    #[test]
    fn loss_never_exceeds_its_bounds() {
        let mut t = SeqTracker::new();
        for seq in 0..10u64 {
            t.observe(seq);
        }
        // More arrived than the sender claims — a nonsensical report must clamp
        // rather than produce a negative loss figure.
        assert_eq!(t.loss_fraction(Some(5)), Some(0.0));
        let empty = SeqTracker::new();
        assert_eq!(empty.loss_fraction(Some(100)), Some(1.0));
    }
}
