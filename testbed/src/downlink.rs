//! The raw UDP capacity controls: wire formats and receiver bookkeeping.
//!
//! Most of this file is the server → client control, described below. The
//! sequence-number bookkeeping ([`SeqTracker`], [`ReorderProfile`],
//! [`loss_fraction`]) and the echo control's own datagram header
//! ([`EchoHeader`]) live here too, so that all three raw controls — the echo,
//! this one, and the client → server ladder in [`crate::uplink`] — are counted
//! by exactly the same code. A reorder distance measured one way and a
//! differently-derived one measured the other way would not be comparable,
//! which is the whole point of having more than one.
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
use serde::{Deserialize, Serialize};

use crate::stats::Summary;

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

// ── Echo control ────────────────────────────────────────────────────────────

/// Marks a datagram of the client → server echo control.
///
/// A distinct magic from [`MAGIC_DATA`] because the two controls answer
/// different questions and a datagram of one must never be counted into the
/// other's ledger, whatever lands on a socket.
pub const MAGIC_ECHO: [u8; 8] = *b"PHRAWEC1";
pub const ECHO_HEADER_LEN: usize = 34;

/// The prefix the echo control writes into each datagram it sends.
///
/// The echo daemon returns datagrams byte for byte and keeps no state, so this
/// header comes back untouched — which is what lets the client number its own
/// traffic without the daemon knowing anything about it, and without changing
/// what is on the wire in either direction: the datagram is the same size and
/// still unauthenticated filler as far as the daemon is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoHeader {
    pub run_nonce: u64,
    pub rung: u16,
    /// Zero-based within the rung.
    pub seq: u64,
    /// The client's own monotonic clock when the datagram went out. Unlike
    /// [`DataHeader::send_unix_ns`] this never crosses a clock boundary — the
    /// same host stamps it and reads it back — so a difference of two of these
    /// is exact.
    pub send_ns: u64,
}

impl EchoHeader {
    /// Write the header into the front of an already-sized datagram buffer.
    ///
    /// In place, for the same reason [`DataHeader::write_into`] is: at the top
    /// of the ladder this runs twenty thousand times a second and an allocation
    /// there would be the sender's own ceiling.
    pub fn write_into(&self, buf: &mut [u8]) {
        if buf.len() < ECHO_HEADER_LEN {
            return;
        }
        buf[0..8].copy_from_slice(&MAGIC_ECHO);
        buf[8..16].copy_from_slice(&self.run_nonce.to_be_bytes());
        buf[16..18].copy_from_slice(&self.rung.to_be_bytes());
        buf[18..26].copy_from_slice(&self.seq.to_be_bytes());
        buf[26..34].copy_from_slice(&self.send_ns.to_be_bytes());
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < ECHO_HEADER_LEN || b[0..8] != MAGIC_ECHO {
            return None;
        }
        Some(Self {
            run_nonce: be64(&b[8..16]),
            rung: be16(&b[16..18]),
            seq: be64(&b[18..26]),
            send_ns: be64(&b[26..34]),
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

/// Sequence numbers the receiver keeps per-datagram state for.
///
/// This is the cap on the receiver's bookkeeping, and it is a hard one: the
/// state is a fixed array of this many slots, allocated once, whatever the
/// rung's length and whatever sequence numbers turn up in it. A rung at the top
/// of the ladder carries a hundred thousand datagrams and a broken or hostile
/// sender can name any of 2^64, so a structure that grew with either would make
/// the receive loop the thing that limits the measurement — or the thing that
/// falls over.
///
/// What happens at the cap is stated in the record rather than hidden. A gap
/// the window slides past unfilled is booked as loss; a jump that skips further
/// ahead than the whole window leaves sequence numbers that can never be
/// attributed either way, and those are counted separately as
/// [`ReorderProfile::gaps_beyond_horizon`]; an arrival further behind than the
/// window reaches cannot be matched to a gap or dup-checked, and lands in
/// [`ReorderProfile::late_beyond_horizon`].
///
/// Four thousand datagrams is roughly a fifth of a second at the top of the
/// ladder and the whole rung at the bottom of it — well past any reordering a
/// path plausibly produces, which is what makes "slid past unfilled" a
/// defensible reading of "lost".
const REORDER_HORIZON: usize = 4096;

/// Ceiling on the individual reorder measurements kept for the distribution.
///
/// The percentiles are wanted exactly, so the samples are kept rather than
/// bucketed — but a rung's arrival count is not under this side's control, so
/// the vector needs an end. Past it the counters keep counting and the
/// distribution stops growing, which is visible because
/// [`ReorderProfile::distance`]'s own `count` no longer matches
/// [`ReorderProfile::late_datagrams`].
const MAX_REORDER_SAMPLES: usize = 1 << 17;

/// The two clocks that make a reordering measurable in time as well as in
/// sequence numbers.
///
/// They are unrelated clocks and are never subtracted from each other: only
/// differences *within* one of them are used, which is what keeps the result
/// free of any assumption about the hosts being synchronised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamps {
    /// The receiver's own monotonic clock, nanoseconds from an arbitrary zero.
    pub recv_ns: u64,
    /// The stamp the sender wrote into the datagram, on the sender's clock.
    pub send_ns: u64,
}

/// What one in-window sequence number is known to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// The window has not reached this sequence number.
    Vacant,
    Arrived,
    /// Expected and not yet seen. Carries the stamps of the arrival that
    /// revealed the gap — the datagram that overtook this one — because the
    /// displacement is measured from there and nowhere else.
    Open(Option<Stamps>),
}

/// How far back the path brings a late datagram from, and how long after.
///
/// A count of reorderings says a path reorders; it does not size anything. A
/// transport's reordering tolerance is a distance and a duration, and both have
/// to clear the tail rather than the middle — hence percentiles rather than a
/// mean. The three distributions answer three different questions:
///
/// - `distance` sizes a packet-threshold rule (how many sequence numbers may
///   pass a datagram before it is declared lost).
/// - `displacement_ns` sizes a receiver-side time threshold: how long after the
///   arrival that revealed a gap the fill actually came. This is the RACK-style
///   quantity, measured entirely on the receiver's clock.
/// - `transit_excess_ns` is that plus the head start the late datagram had over
///   its overtaker, taken from the two send stamps — how much longer it took to
///   cross the path. The two send stamps and the two arrival stamps are each
///   subtracted within their own clock, so no offset estimate enters.
///
/// The gap counters split what a bare reordering count conflates. A gap a later
/// arrival filled is reordering; one the window slid past is loss; one still
/// open when the rung ended is neither, and is reported as its own quantity
/// because the datagram may well have arrived a millisecond after the rung
/// stopped listening.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReorderProfile {
    /// Sequence numbers the receiver kept state for. Stated in the record so a
    /// reader can tell a measured tail from one clipped by the instrument.
    pub horizon: u64,
    /// Datagrams that arrived after a higher-numbered one already had.
    pub late_datagrams: u64,
    /// Sequence numbers behind the highest seen, over late datagrams.
    pub distance: Summary,
    /// Nanoseconds between the arrival that revealed the gap and the fill.
    pub displacement_ns: Summary,
    /// Nanoseconds of extra transit relative to the overtaking datagram.
    pub transit_excess_ns: Summary,
    /// Gaps a later arrival filled — reordering.
    pub gaps_filled: u64,
    /// Gaps the horizon slid past unfilled — loss.
    pub gaps_lost: u64,
    /// Gaps still open when the rung ended — neither, and deliberately not
    /// folded into either.
    pub gaps_open_at_end: u64,
    /// Sequence numbers a forward jump skipped by more than the whole window,
    /// which can never be filled and were never observed to be lost.
    pub gaps_beyond_horizon: u64,
    /// Arrivals too far behind the highest seen to match to a gap. Counted as
    /// reordering and as arrivals, but they contribute no distance sample.
    pub late_beyond_horizon: u64,
}

/// Counts arrivals, reordering and duplication from a stream of sequence
/// numbers, and keeps the ledger that separates reordering from loss.
///
/// Aggregate loss is deliberately *not* derived here from gaps: a gap at the
/// receiver is indistinguishable from a datagram the sender never sent, and the
/// sender's own count is the only honest denominator. See
/// [`SeqTracker::loss_fraction`]. The per-gap classification in
/// [`ReorderProfile`] is a different statement — it says which of the arrivals
/// that *did* happen came late — and the two are reported side by side rather
/// than reconciled into one number.
#[derive(Debug)]
pub struct SeqTracker {
    highest: Option<u64>,
    received: u64,
    duplicates: u64,
    reordered: u64,
    slots: Box<[Slot]>,
    gaps_filled: u64,
    gaps_lost: u64,
    gaps_beyond_horizon: u64,
    late_beyond_horizon: u64,
    distance: Vec<f64>,
    displacement_ns: Vec<f64>,
    transit_excess_ns: Vec<f64>,
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
            slots: vec![Slot::Vacant; REORDER_HORIZON].into_boxed_slice(),
            gaps_filled: 0,
            gaps_lost: 0,
            gaps_beyond_horizon: 0,
            late_beyond_horizon: 0,
            distance: Vec::new(),
            displacement_ns: Vec::new(),
            transit_excess_ns: Vec::new(),
        }
    }

    /// Record one arrival whose timing is unknown. The sequence-distance
    /// distribution is still filled; the two time distributions are not.
    pub fn observe(&mut self, seq: u64) -> bool {
        self.observe_at(seq, None)
    }

    /// Record one arrival together with the clocks that date it.
    ///
    /// Returns false when the datagram was a duplicate, so the caller can keep
    /// its byte count to distinct datagrams.
    pub fn observe_stamped(&mut self, seq: u64, stamps: Stamps) -> bool {
        self.observe_at(seq, Some(stamps))
    }

    fn observe_at(&mut self, seq: u64, stamps: Option<Stamps>) -> bool {
        let Some(highest) = self.highest else {
            // The first arrival sets the baseline. Sequence numbers below it
            // were sent and did not turn up, so as much of that range as the
            // window reaches is opened as gaps rather than assumed away — a
            // rung whose opening datagrams are lost would otherwise account for
            // none of them.
            let floor = seq.saturating_sub(REORDER_HORIZON as u64 - 1);
            for below in floor..seq {
                self.set(below, Slot::Open(stamps));
            }
            self.highest = Some(seq);
            self.set(seq, Slot::Arrived);
            self.received = 1;
            return true;
        };

        if seq > highest {
            self.advance(highest, seq, stamps);
            self.highest = Some(seq);
            self.received += 1;
            return true;
        }

        // At or below the high-water mark: a duplicate, or a datagram overtaken
        // in flight.
        let behind = highest - seq;
        if behind >= REORDER_HORIZON as u64 {
            // Further back than the window reaches: it cannot be matched to a
            // gap and cannot be dup-checked. Counting it as an arrival is the
            // conservative choice, since treating a real datagram as a
            // duplicate would understate what the path delivered.
            self.late_beyond_horizon += 1;
            self.reordered += 1;
            self.received += 1;
            return true;
        }

        match self.slot_of(seq) {
            Slot::Arrived => {
                self.duplicates += 1;
                false
            }
            Slot::Open(revealed) => {
                self.set(seq, Slot::Arrived);
                self.gaps_filled += 1;
                self.reordered += 1;
                self.received += 1;
                self.record(behind, revealed, stamps);
                true
            }
            // Every in-window sequence number at or below the high-water mark
            // is opened as a gap the moment the window reaches it, so this arm
            // is not reachable. Handled as an unattributed late arrival rather
            // than assumed away, because the alternative is a silent miscount.
            Slot::Vacant => {
                self.set(seq, Slot::Arrived);
                self.reordered += 1;
                self.received += 1;
                self.record(behind, None, stamps);
                true
            }
        }
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

    /// The reorder distributions and the gap ledger as they stand.
    ///
    /// Non-consuming, and the gaps still open are counted at the moment it is
    /// called — so calling it is what draws the line between "still open" and
    /// anything that arrives afterwards.
    pub fn profile(&self) -> ReorderProfile {
        ReorderProfile {
            horizon: REORDER_HORIZON as u64,
            late_datagrams: self.reordered,
            distance: Summary::of(&self.distance),
            displacement_ns: Summary::of(&self.displacement_ns),
            transit_excess_ns: Summary::of(&self.transit_excess_ns),
            gaps_filled: self.gaps_filled,
            gaps_lost: self.gaps_lost,
            gaps_open_at_end: self
                .slots
                .iter()
                .filter(|s| matches!(s, Slot::Open(_)))
                .count() as u64,
            gaps_beyond_horizon: self.gaps_beyond_horizon,
            late_beyond_horizon: self.late_beyond_horizon,
        }
    }

    /// The fraction of the sender's datagrams that never arrived.
    ///
    /// `None` when the sender's count is unknown — without it there is no
    /// denominator, and inventing one from the highest sequence number seen
    /// would silently report zero loss for a rung that was cut off early.
    pub fn loss_fraction(&self, sender_datagrams: Option<u64>) -> Option<f64> {
        loss_fraction(self.received, sender_datagrams)
    }

    /// Move the high-water mark from `highest` to `seq`, opening the sequence
    /// numbers stepped over and retiring whatever leaves the window.
    fn advance(&mut self, highest: u64, seq: u64, stamps: Option<Stamps>) {
        let advance = seq - highest;
        if advance >= REORDER_HORIZON as u64 {
            // The jump replaces the whole window. Everything still open in it
            // left unfilled, and the sequence numbers beyond the window's reach
            // can never be attributed at all — the one case where the ledger
            // has to admit it does not know, rather than book a loss it never
            // observed.
            for i in 0..self.slots.len() {
                if matches!(self.slots[i], Slot::Open(_)) {
                    self.gaps_lost += 1;
                }
                self.slots[i] = Slot::Open(stamps);
            }
            self.gaps_beyond_horizon += advance - REORDER_HORIZON as u64;
            self.set(seq, Slot::Arrived);
            return;
        }
        // Each slot about to be reused holds the state of the sequence number
        // one window back, which is exactly the one leaving.
        for y in (highest + 1)..=seq {
            if matches!(self.slot_of(y), Slot::Open(_)) {
                self.gaps_lost += 1;
            }
            let state = if y == seq {
                Slot::Arrived
            } else {
                Slot::Open(stamps)
            };
            self.set(y, state);
        }
    }

    fn record(&mut self, distance: u64, revealed: Option<Stamps>, arrival: Option<Stamps>) {
        if self.distance.len() >= MAX_REORDER_SAMPLES {
            return;
        }
        self.distance.push(distance as f64);
        let (Some(r), Some(a)) = (revealed, arrival) else {
            return;
        };
        let displacement = a.recv_ns.saturating_sub(r.recv_ns);
        // The head start the late datagram had over the one that overtook it,
        // on the sender's clock. Added to the displacement it gives the extra
        // time the path took over it, with both clock offsets cancelling.
        let head_start = r.send_ns.saturating_sub(a.send_ns);
        self.displacement_ns.push(displacement as f64);
        self.transit_excess_ns
            .push(displacement.saturating_add(head_start) as f64);
    }

    fn index(seq: u64) -> usize {
        (seq % REORDER_HORIZON as u64) as usize
    }

    fn set(&mut self, seq: u64, state: Slot) {
        let i = Self::index(seq);
        self.slots[i] = state;
    }

    fn slot_of(&self, seq: u64) -> Slot {
        self.slots[Self::index(seq)]
    }
}

/// The fraction of a sender's datagrams that never arrived.
///
/// Free-standing because the two ladders arrive at it from opposite sides: on
/// the downstream one the receiver holds the tracker and the sender's count
/// comes over the wire, on the uplink one it is the other way round. One
/// definition means a loss figure means the same thing whichever direction
/// produced it — which is the entire point of having both.
///
/// `None` when the sender's count is unknown: without it there is no
/// denominator, and inventing one from what happened to arrive would report a
/// rung that was cut off early as lossless.
pub fn loss_fraction(received: u64, sender_datagrams: Option<u64>) -> Option<f64> {
    let sent = sender_datagrams?;
    if sent == 0 {
        return None;
    }
    let ratio = received.min(sent) as f64 / sent as f64;
    Some((1.0 - ratio).clamp(0.0, 1.0))
}

// ── Fixed-width readers ─────────────────────────────────────────────────────
//
// Shared with [`crate::uplink`], which encodes its own datagrams at the same
// offsets in the same order: two copies of these would be two places for an
// endianness to drift.

pub(crate) fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

pub(crate) fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub(crate) fn be64(b: &[u8]) -> u64 {
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

        let eh = EchoHeader {
            run_nonce: 0x0102_0304_0506_0708,
            rung: 1,
            seq: u64::MAX,
            send_ns: 987_654_321,
        };
        let mut ebuf = vec![0u8; DEFAULT_PAYLOAD];
        eh.write_into(&mut ebuf);
        assert_eq!(EchoHeader::decode(&ebuf), Some(eh));

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

    /// The two controls run on different ports but must not be able to read
    /// each other's datagrams even if one did land on the other's socket: a
    /// downstream burst counted as echo returns would report a round trip that
    /// never happened.
    #[test]
    fn the_two_controls_cannot_read_each_others_datagrams() {
        let mut buf = vec![0u8; DEFAULT_PAYLOAD];
        DataHeader {
            run_nonce: 1,
            rung: 0,
            seq: 7,
            send_unix_ns: 5,
        }
        .write_into(&mut buf);
        assert_eq!(EchoHeader::decode(&buf), None);

        let mut buf = vec![0u8; DEFAULT_PAYLOAD];
        EchoHeader {
            run_nonce: 1,
            rung: 0,
            seq: 7,
            send_ns: 5,
        }
        .write_into(&mut buf);
        assert_eq!(DataHeader::decode(&buf), None);
        assert_eq!(Report::decode(&buf), None);
        assert_eq!(Challenge::decode(&buf), None);
        assert_eq!(Request::decode(&buf), None);
        assert_eq!(EchoHeader::decode(&buf[..ECHO_HEADER_LEN - 1]), None);
        assert_eq!(EchoHeader::decode(&[]), None);
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

    /// The uplink ladder holds the two halves on opposite hosts — the receiver's
    /// count comes over the wire and the sender's is local — so it reaches this
    /// arithmetic without a tracker. Both callers must get the same answer from
    /// the same pair of numbers, or a loss figure means one thing downstream and
    /// another upstream.
    #[test]
    fn loss_has_one_definition_whichever_side_holds_the_ledger() {
        let mut t = SeqTracker::new();
        for seq in 0..900u64 {
            t.observe(seq);
        }
        assert_eq!(t.loss_fraction(Some(1000)), loss_fraction(900, Some(1000)));
        let l = loss_fraction(900, Some(1000)).expect("both counts known");
        assert!((l - 0.10).abs() < 1e-9, "got {l}");

        // The same edges the method has: no denominator, a nonsensical one, and
        // a receiver that outcounted the sender.
        assert_eq!(loss_fraction(10, None), None);
        assert_eq!(loss_fraction(10, Some(0)), None);
        assert_eq!(loss_fraction(10, Some(5)), Some(0.0));
        assert_eq!(loss_fraction(0, Some(100)), Some(1.0));
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
        t.observe(REORDER_HORIZON as u64 * 2);
        assert!(t.observe(1));
        assert_eq!(t.received(), 3);
        assert_eq!(t.reordered(), 1);
    }

    /// A long stream must not accumulate false duplicates as the bitmap wraps.
    #[test]
    fn the_window_slides_without_leaving_stale_marks() {
        let mut t = SeqTracker::new();
        for seq in 0..(REORDER_HORIZON as u64 * 5) {
            assert!(t.observe(seq), "seq {seq} was wrongly seen as a duplicate");
        }
        assert_eq!(t.duplicates(), 0);
        assert_eq!(t.received(), REORDER_HORIZON as u64 * 5);

        // A jump past the window clears it wholesale; nothing behind the jump
        // may still read as marked.
        let far = REORDER_HORIZON as u64 * 20;
        t.observe(far);
        assert!(t.observe(far - 1), "the swept region must be clear");
        assert_eq!(t.duplicates(), 0);
    }

    // ── Reorder distance and the loss/reordering split ──────────────────────
    //
    // "The path reorders" sizes nothing. A transport's reordering tolerance is
    // a distance and a duration, so these pin both: how far back a late
    // datagram came from, how long after the datagram that overtook it it
    // arrived, and — separately — which gaps were filled and which never were.

    /// Sequence `seq` sent at `seq` µs and arriving at `at` ns on the
    /// receiver's clock. The two clocks are deliberately unrelated, as they are
    /// on the wire.
    fn at(seq: u64, recv_ns: u64) -> Stamps {
        Stamps {
            recv_ns,
            send_ns: seq.saturating_mul(1_000),
        }
    }

    #[test]
    fn an_in_order_stream_leaves_no_gaps_at_all() {
        let mut t = SeqTracker::new();
        for seq in 0..10_000u64 {
            assert!(t.observe_stamped(seq, at(seq, seq * 1_000_000)));
        }
        let p = t.profile();
        assert_eq!(p.late_datagrams, 0);
        assert_eq!(p.gaps_filled, 0);
        assert_eq!(p.gaps_lost, 0);
        assert_eq!(p.gaps_open_at_end, 0);
        assert_eq!(p.gaps_beyond_horizon, 0);
        assert_eq!(p.distance.count, 0, "nothing arrived late to measure");
    }

    /// The single-datagram case, computed by hand: 3 is overtaken by 4 and 5,
    /// so it lands two sequence numbers behind the highest seen, five
    /// microseconds after the arrival that revealed the gap — and, correcting
    /// for the microsecond head start it had on its overtaker, six microseconds
    /// of extra transit.
    #[test]
    fn one_late_datagram_carries_a_distance_a_displacement_and_an_excess() {
        let mut t = SeqTracker::new();
        for (seq, recv) in [
            (0u64, 1_000u64),
            (1, 2_000),
            (2, 3_000),
            (4, 4_000),
            (5, 5_000),
        ] {
            assert!(t.observe_stamped(seq, at(seq, recv)));
        }
        assert!(t.observe_stamped(3, at(3, 9_000)));

        let p = t.profile();
        assert_eq!(p.late_datagrams, 1);
        assert_eq!(p.gaps_filled, 1);
        assert_eq!(p.gaps_lost, 0);
        assert_eq!(p.gaps_open_at_end, 0);
        assert_eq!(p.distance.count, 1);
        assert_eq!(p.distance.max, 2.0, "highest seen was 5, this was 3");
        assert_eq!(
            p.displacement_ns.max, 5_000.0,
            "seq 4 revealed the gap at 4000 ns; seq 3 filled it at 9000"
        );
        assert_eq!(
            p.transit_excess_ns.max, 6_000.0,
            "displacement plus the 1 µs head start seq 3 had over seq 4"
        );
    }

    /// A run of late datagrams, with every percentile hand-computed. The point
    /// of the distribution is that the mean would hide the tail: here the mean
    /// distance is 54 and the p99 is 99, and a tolerance sized on the former
    /// declares a fifth of these lost.
    #[test]
    fn a_run_of_late_datagrams_reports_a_distribution_not_a_mean() {
        const LATE: [u64; 10] = [100, 110, 120, 130, 140, 150, 160, 170, 180, 190];
        let mut t = SeqTracker::new();

        let mut idx = 0u64;
        for seq in 0..200u64 {
            if LATE.contains(&seq) {
                continue;
            }
            assert!(t.observe_stamped(seq, at(seq, idx * 1_000_000)));
            idx += 1;
        }
        for (n, seq) in LATE.iter().enumerate() {
            assert!(t.observe_stamped(*seq, at(*seq, (190 + n as u64) * 1_000_000)));
        }

        let p = t.profile();
        assert_eq!(p.late_datagrams, 10);
        assert_eq!(p.gaps_filled, 10);
        assert_eq!(p.gaps_lost, 0);
        assert_eq!(p.gaps_open_at_end, 0);

        // Distances are 199 − seq: 99, 89, …, 9. Nearest rank over ten samples
        // puts p50 at the 5th, p90 at the 9th and p99 at the 10th.
        assert_eq!(p.distance.count, 10);
        assert_eq!(p.distance.p50, 49.0);
        assert_eq!(p.distance.p90, 89.0);
        assert_eq!(p.distance.p99, 99.0);
        assert_eq!(p.distance.max, 99.0);

        // Displacements, in the same order: 90, 82, 74, …, 18 ms.
        assert_eq!(p.displacement_ns.p50, 50e6);
        assert_eq!(p.displacement_ns.p90, 82e6);
        assert_eq!(p.displacement_ns.p99, 90e6);
        assert_eq!(p.displacement_ns.max, 90e6);

        // Each of these was overtaken by the datagram sent 1 µs after it, so
        // the excess is uniformly one microsecond above the displacement.
        assert_eq!(p.transit_excess_ns.p50, 50e6 + 1_000.0);
        assert_eq!(p.transit_excess_ns.max, 90e6 + 1_000.0);
    }

    /// The distinction the old counter could not draw: a gap the horizon slid
    /// past is loss, and nothing else in the record says so.
    #[test]
    fn a_gap_the_horizon_slides_past_is_loss_not_reordering() {
        let mut t = SeqTracker::new();
        let horizon = t.profile().horizon;
        for seq in 0..=(horizon + 1000) {
            if seq == 10 {
                continue;
            }
            t.observe_stamped(seq, at(seq, seq * 1_000_000));
        }
        let p = t.profile();
        assert_eq!(p.gaps_lost, 1, "seq 10 was never going to arrive");
        assert_eq!(p.gaps_filled, 0);
        assert_eq!(p.gaps_open_at_end, 0);
        assert_eq!(p.late_datagrams, 0, "loss is not reordering");
    }

    /// The other half of the same distinction: a gap the rung ended on is
    /// neither, and must be reported as its own quantity rather than folded
    /// into loss (the datagram may well have arrived a millisecond later).
    #[test]
    fn a_gap_still_open_when_the_rung_ends_is_classified_as_neither() {
        let mut t = SeqTracker::new();
        for seq in 0..=100u64 {
            if seq == 50 {
                continue;
            }
            t.observe_stamped(seq, at(seq, seq * 1_000_000));
        }
        let p = t.profile();
        assert_eq!(p.gaps_open_at_end, 1);
        assert_eq!(p.gaps_lost, 0, "the horizon never reached it");
        assert_eq!(p.gaps_filled, 0);
    }

    /// A rung whose first datagrams never arrive still accounts for them: the
    /// baseline opens the sequence numbers below the first arrival rather than
    /// pretending the stream started there.
    #[test]
    fn sequence_numbers_below_the_first_arrival_are_still_accounted() {
        let mut t = SeqTracker::new();
        for seq in 3..=100u64 {
            t.observe_stamped(seq, at(seq, seq * 1_000_000));
        }
        assert_eq!(
            t.profile().gaps_open_at_end,
            3,
            "0, 1 and 2 are unaccounted"
        );

        // And one of them turning up late is a fill like any other.
        assert!(t.observe_stamped(1, at(1, 200_000_000)));
        let p = t.profile();
        assert_eq!(p.gaps_filled, 1);
        assert_eq!(p.gaps_open_at_end, 2);
        assert_eq!(p.distance.max, 99.0, "highest seen was 100");
    }

    #[test]
    fn a_duplicate_is_neither_a_fill_nor_a_loss() {
        let mut t = SeqTracker::new();
        for seq in 0..100u64 {
            t.observe_stamped(seq, at(seq, seq * 1_000_000));
        }
        assert!(!t.observe_stamped(50, at(50, 200_000_000)));
        let p = t.profile();
        assert_eq!(p.gaps_filled, 0);
        assert_eq!(p.late_datagrams, 0);
        assert_eq!(p.distance.count, 0);
        assert_eq!(t.duplicates(), 1);

        // A late datagram that then repeats fills its gap exactly once.
        let mut u = SeqTracker::new();
        for seq in [0u64, 1, 3] {
            u.observe_stamped(seq, at(seq, seq * 1_000_000));
        }
        assert!(u.observe_stamped(2, at(2, 9_000_000)));
        assert!(!u.observe_stamped(2, at(2, 10_000_000)));
        let p = u.profile();
        assert_eq!(p.gaps_filled, 1);
        assert_eq!(p.distance.count, 1);
        assert_eq!(u.duplicates(), 1);
    }

    /// The bound the receiver runs under, stated as a test: a sender — broken
    /// or hostile — can name any sequence number in a 64-bit space, and the
    /// bookkeeping must not follow it. Nothing here may allocate per skipped
    /// sequence number, and the record must say how much it could not attribute
    /// rather than quietly booking it as loss.
    ///
    /// If the forward-jump bound is taken out — the obvious "just track every
    /// gap" version — this test does not fail, it never returns, because the
    /// obvious version walks 2^64 sequence numbers. That is the failure mode
    /// the bound exists for, and it is why the assertion is on the horizon
    /// rather than on the count of gaps the ledger happens to hold.
    #[test]
    fn a_wild_sequence_number_is_bounded_not_allocated() {
        let mut t = SeqTracker::new();
        let horizon = t.profile().horizon;

        t.observe_stamped(0, at(0, 0));
        t.observe_stamped(u64::MAX, at(u64::MAX, 1_000_000));
        let p = t.profile();
        assert_eq!(
            p.gaps_open_at_end,
            horizon - 1,
            "only the horizon's worth of the jump is tracked"
        );
        assert_eq!(
            p.gaps_beyond_horizon,
            u64::MAX - horizon,
            "the rest is unattributable and says so"
        );
        assert_eq!(p.gaps_lost, 0, "an unreachable gap is not a measured loss");

        // An arrival further behind than the horizon cannot be matched to a
        // gap; it counts as an arrival and as reordering, and is called out.
        assert!(t.observe_stamped(1, at(1, 2_000_000)));
        let p = t.profile();
        assert_eq!(p.late_beyond_horizon, 1);
        assert_eq!(p.gaps_filled, 0);
        assert_eq!(p.late_datagrams, 1);
        assert_eq!(t.received(), 3);
    }

    /// Whatever the arrival order, the reordering counter and the ledger must
    /// agree: every late datagram is either a gap it filled or one the horizon
    /// had already let go.
    #[test]
    fn the_ledger_and_the_reordering_counter_never_disagree() {
        let mut t = SeqTracker::new();
        let mut order: Vec<u64> = (0..2_000).collect();
        // A deterministic shuffle with a long-distance component.
        for i in 0..order.len() {
            let j = (i * 7 + 13) % order.len();
            order.swap(i, j);
        }
        for (n, seq) in order.iter().enumerate() {
            t.observe_stamped(*seq, at(*seq, n as u64 * 1_000));
        }
        let p = t.profile();
        assert_eq!(p.late_datagrams, t.reordered());
        assert_eq!(p.gaps_filled + p.late_beyond_horizon, p.late_datagrams);
        assert_eq!(p.gaps_lost, 0, "everything did arrive");
        assert_eq!(p.gaps_open_at_end, 0);
        assert_eq!(t.received(), 2_000);
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
