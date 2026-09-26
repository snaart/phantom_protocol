//! The raw UDP upstream control: wire formats for the client → server ladder.
//!
//! ## Why it exists
//!
//! Every leg reports an `upload` figure and none of them could be normalised.
//! The harness had three raw controls — a TCP echo, a UDP echo, and the one-way
//! [`crate::downlink`] source — and the first two are round trips, so a byte
//! counted in either crossed the path twice and bounds neither direction alone.
//! The third is one way and covers server → client. Upload, the direction this
//! project cares most about, was therefore quoted against no control at all,
//! and every campaign's caveats had to say so.
//!
//! This is the mirror of the downstream ladder, aimed the other way: the client
//! paces raw datagrams at each offered rate and the daemon states, in its own
//! words, what it received over its own observation window.
//!
//! ## What differs from the downstream ladder, and why
//!
//! The two ladders offer identically shaped traffic — the same
//! [`crate::pacing::Pacer`], the same rungs, the same datagram size, the same
//! sequence-numbered header, the same [`crate::downlink::SeqTracker`]
//! bookkeeping — because the two numbers are meant to be read side by side.
//! Three things are not the same, and each is forced:
//!
//! 1. **The receiver's whole account crosses the wire.** Downstream, the
//!    receiver is the client, so it keeps its own ledger and needs only the
//!    sender's totals back. Upstream the receiver is the daemon, so the ledger
//!    itself — arrivals, duplicates, and the full reorder distribution — has to
//!    travel, which is what [`Report`] carries and why it is the one message
//!    here with a non-trivial encoding.
//! 2. **The rung is armed before it starts.** [`SeqTracker`] opens the sequence
//!    numbers below its first arrival as gaps, so datagrams that reach the
//!    daemon before it knows a rung exists would be booked as loss the path
//!    never caused. The daemon answers a cookie-bearing request with [`Ready`]
//!    and the client sends nothing until it arrives.
//! 3. **A refusal is explicit.** Downstream, a declined rung is reported as a
//!    sender that achieved zero, which reads correctly as inadmissible. Here the
//!    same silence would read as a receiver that saw nothing — that is, as a
//!    path that swallowed the entire rung, which is a measurement and a false
//!    one. So [`Ready::accepted`] says no in a field.
//!
//! ## The one thing that is not raw
//!
//! The same return-routability cookie the downstream source uses, minted by the
//! same [`crate::downlink::CookieMinter`], for a different reason. There the
//! cookie stops a 40-byte request turning into a burst aimed at a forged
//! address. Here nothing is amplified — the daemon's replies are smaller than
//! what provokes them — but an armed rung costs the daemon a receiver ledger,
//! and a ledger that any spoofed source address can allocate is a table an
//! attacker fills. The cookie proves the asker can receive where it claims to
//! be, and the concurrency bound does the rest.

use crate::downlink::{be16, be32, be64, ReorderProfile, COOKIE_LEN};
use crate::stats::Summary;

// ── Message kinds ───────────────────────────────────────────────────────────
//
// Five fixed-layout datagrams behind eight-byte magics, distinct from the
// downstream control's for the reason its own note gives: these listeners sit
// on public ports, and a datagram of one control must never be counted into
// another's ledger whatever lands on a socket.

pub const MAGIC_REQUEST: [u8; 8] = *b"PHRAWUQ1";
pub const MAGIC_CHALLENGE: [u8; 8] = *b"PHRAWUC1";
pub const MAGIC_READY: [u8; 8] = *b"PHRAWUY1";
pub const MAGIC_DATA: [u8; 8] = *b"PHRAWUD1";
pub const MAGIC_REPORT: [u8; 8] = *b"PHRAWUR1";

pub const REQUEST_LEN: usize = 40;
pub const CHALLENGE_LEN: usize = 28;
pub const READY_LEN: usize = 19;
/// Fixed prefix every uplink data datagram carries; the rest is filler.
pub const DATA_HEADER_LEN: usize = 34;

/// One [`Summary`] on the wire: the count, then nine doubles.
const SUMMARY_LEN: usize = 8 + 9 * 8;
/// One [`ReorderProfile`]: two counters, three distributions, five more counters.
const PROFILE_LEN: usize = 2 * 8 + 3 * SUMMARY_LEN + 5 * 8;
pub const REPORT_LEN: usize = 8 + 8 + 2 + 6 * 8 + PROFILE_LEN;

/// The receiver's whole account has to fit in one datagram, because it is sent
/// unacknowledged like everything else here and a fragmented one would be lost
/// whenever any of its fragments was.
const _: () = assert!(
    REPORT_LEN <= crate::downlink::MAX_PAYLOAD,
    "the uplink report must fit inside one unfragmented datagram"
);

/// The two ladders' data headers are the same 34 bytes, which is what lets one
/// [`crate::downlink::SeqTracker`] count both directions and one
/// `MIN_PAYLOAD` bound cover both.
const _: () = assert!(
    DATA_HEADER_LEN == crate::downlink::DATA_HEADER_LEN,
    "the two directions must number their datagrams in the same shape"
);

// ── Request ─────────────────────────────────────────────────────────────────

/// Client → daemon: "I am about to send `offered_kbps` for `duration_ms`".
///
/// The same fields, in the same order and at the same offsets, as
/// [`crate::downlink::Request`] — a rung is described in one vocabulary
/// whichever way it is about to run. Only the magic differs, and a test pins
/// that the rest of the bytes agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// Distinguishes one probe run's traffic from another's on a shared port.
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

/// Daemon → client: "come back with this".
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

// ── Ready ───────────────────────────────────────────────────────────────────

/// Daemon → client: the rung is armed, or it is declined.
///
/// This message has no counterpart downstream and exists for two reasons the
/// module note states in full: a receiver ledger that starts after the first
/// datagram books the ones before it as loss, and a refusal that arrives as
/// silence is indistinguishable from a path that swallowed the rung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ready {
    pub run_nonce: u64,
    pub rung: u16,
    /// False when the daemon declined to observe this rung, in which case
    /// nothing about the path can be read from it.
    pub accepted: bool,
}

impl Ready {
    pub fn encode(&self) -> [u8; READY_LEN] {
        let mut b = [0u8; READY_LEN];
        b[0..8].copy_from_slice(&MAGIC_READY);
        b[8..16].copy_from_slice(&self.run_nonce.to_be_bytes());
        b[16..18].copy_from_slice(&self.rung.to_be_bytes());
        b[18] = u8::from(self.accepted);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < READY_LEN || b[0..8] != MAGIC_READY {
            return None;
        }
        Some(Self {
            run_nonce: be64(&b[8..16]),
            rung: be16(&b[16..18]),
            accepted: b[18] != 0,
        })
    }
}

// ── Data ────────────────────────────────────────────────────────────────────

/// The fixed prefix of one paced datagram on its way up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    pub run_nonce: u64,
    pub rung: u16,
    /// Zero-based within the rung, incremented once per datagram put on the
    /// socket — what makes loss, reordering and duplication separable
    /// quantities rather than one byte-count shortfall.
    pub seq: u64,
    /// The sender's own clock when the datagram went out. It crosses a host
    /// boundary, so it is never subtracted from the receiver's clock; only
    /// differences within it are used, exactly as downstream.
    pub send_unix_ns: u64,
}

impl DataHeader {
    /// Write the header into the front of an already-sized datagram buffer.
    ///
    /// In place rather than allocating: at the top of the ladder this runs
    /// twenty thousand times a second and a per-datagram allocation there would
    /// be the sender's own bottleneck — which is the confound this control
    /// exists to rule out, not to introduce.
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

/// Daemon → client, after the rung: what the *receiver* counted.
///
/// This is the honest number on an upload and the client's own is not: `send()`
/// buffers, and a sender counts what it handed to a socket. Everything here is
/// measured on the daemon over the daemon's own observation window — first
/// arrival to last — so the interval excludes the request's round trip and the
/// client's start-up, exactly as the downstream ladder's receiver-side window
/// does.
///
/// Loss is deliberately absent: a gap at a receiver is indistinguishable from a
/// datagram the sender never sent, so the fraction is computed by the client,
/// which is the side that knows the denominator. That is the same rule the
/// downstream ladder follows with the sides swapped.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub run_nonce: u64,
    pub rung: u16,
    /// Distinct datagrams that arrived; a duplicate is not a second arrival.
    pub received_datagrams: u64,
    pub received_bytes: u64,
    /// Bytes of the first arrival, so the client can measure the rate over the
    /// interval those arrivals span: `n` datagrams span `n - 1` gaps, and
    /// counting all `n` over that span overstates the rate at low counts. The
    /// downstream ladder drops the first datagram for the same reason, and the
    /// field exists so both do the same arithmetic rather than nearly.
    pub first_datagram_bytes: u64,
    pub reordered_datagrams: u64,
    pub duplicate_datagrams: u64,
    /// First arrival to last arrival, on the receiver's monotonic clock.
    pub observed_window_ns: u64,
    /// How far back and how long after the path brought the late ones, plus the
    /// gap-by-gap split of reordering from loss.
    pub reorder: ReorderProfile,
}

impl Report {
    pub fn encode(&self) -> [u8; REPORT_LEN] {
        let mut b = [0u8; REPORT_LEN];
        b[0..8].copy_from_slice(&MAGIC_REPORT);
        b[8..16].copy_from_slice(&self.run_nonce.to_be_bytes());
        b[16..18].copy_from_slice(&self.rung.to_be_bytes());
        b[18..26].copy_from_slice(&self.received_datagrams.to_be_bytes());
        b[26..34].copy_from_slice(&self.received_bytes.to_be_bytes());
        b[34..42].copy_from_slice(&self.first_datagram_bytes.to_be_bytes());
        b[42..50].copy_from_slice(&self.reordered_datagrams.to_be_bytes());
        b[50..58].copy_from_slice(&self.duplicate_datagrams.to_be_bytes());
        b[58..66].copy_from_slice(&self.observed_window_ns.to_be_bytes());
        write_profile(&mut b[66..], &self.reorder);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < REPORT_LEN || b[0..8] != MAGIC_REPORT {
            return None;
        }
        Some(Self {
            run_nonce: be64(&b[8..16]),
            rung: be16(&b[16..18]),
            received_datagrams: be64(&b[18..26]),
            received_bytes: be64(&b[26..34]),
            first_datagram_bytes: be64(&b[34..42]),
            reordered_datagrams: be64(&b[42..50]),
            duplicate_datagrams: be64(&b[50..58]),
            observed_window_ns: be64(&b[58..66]),
            reorder: read_profile(&b[66..]),
        })
    }
}

fn write_profile(b: &mut [u8], p: &ReorderProfile) {
    b[0..8].copy_from_slice(&p.horizon.to_be_bytes());
    b[8..16].copy_from_slice(&p.late_datagrams.to_be_bytes());
    write_summary(&mut b[16..], &p.distance);
    write_summary(&mut b[16 + SUMMARY_LEN..], &p.displacement_ns);
    write_summary(&mut b[16 + 2 * SUMMARY_LEN..], &p.transit_excess_ns);
    let tail = 16 + 3 * SUMMARY_LEN;
    b[tail..tail + 8].copy_from_slice(&p.gaps_filled.to_be_bytes());
    b[tail + 8..tail + 16].copy_from_slice(&p.gaps_lost.to_be_bytes());
    b[tail + 16..tail + 24].copy_from_slice(&p.gaps_open_at_end.to_be_bytes());
    b[tail + 24..tail + 32].copy_from_slice(&p.gaps_beyond_horizon.to_be_bytes());
    b[tail + 32..tail + 40].copy_from_slice(&p.late_beyond_horizon.to_be_bytes());
}

fn read_profile(b: &[u8]) -> ReorderProfile {
    let tail = 16 + 3 * SUMMARY_LEN;
    ReorderProfile {
        horizon: be64(&b[0..8]),
        late_datagrams: be64(&b[8..16]),
        distance: read_summary(&b[16..]),
        displacement_ns: read_summary(&b[16 + SUMMARY_LEN..]),
        transit_excess_ns: read_summary(&b[16 + 2 * SUMMARY_LEN..]),
        gaps_filled: be64(&b[tail..tail + 8]),
        gaps_lost: be64(&b[tail + 8..tail + 16]),
        gaps_open_at_end: be64(&b[tail + 16..tail + 24]),
        gaps_beyond_horizon: be64(&b[tail + 24..tail + 32]),
        late_beyond_horizon: be64(&b[tail + 32..tail + 40]),
    }
}

fn write_summary(b: &mut [u8], s: &Summary) {
    b[0..8].copy_from_slice(&(s.count as u64).to_be_bytes());
    for (i, v) in [
        s.min, s.max, s.mean, s.stddev, s.p50, s.p90, s.p95, s.p99, s.p999,
    ]
    .iter()
    .enumerate()
    {
        let at = 8 + i * 8;
        b[at..at + 8].copy_from_slice(&v.to_bits().to_be_bytes());
    }
}

fn read_summary(b: &[u8]) -> Summary {
    let f = |i: usize| finite(f64::from_bits(be64(&b[8 + i * 8..16 + i * 8])));
    Summary {
        count: be64(&b[0..8]).min(usize::MAX as u64) as usize,
        min: f(0),
        max: f(1),
        mean: f(2),
        stddev: f(3),
        p50: f(4),
        p90: f(5),
        p95: f(6),
        p99: f(7),
        p999: f(8),
    }
}

/// Refuse a non-finite double read off the wire.
///
/// The report crosses a public port, so any bit pattern can turn up in it, and
/// `NaN` has no JSON encoding: one corrupt datagram would otherwise cost the
/// whole rung's record rather than one wrong number. `Summary::of` already
/// drops non-finite samples on the way in, so a legitimate report never carries
/// one and nothing measured is lost here.
fn finite(x: f64) -> f64 {
    if x.is_finite() {
        x
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downlink;

    fn demo_profile() -> ReorderProfile {
        ReorderProfile {
            horizon: 4096,
            late_datagrams: 12,
            distance: Summary::of_u64(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            displacement_ns: Summary::of_u64(&[1_000_000; 12]),
            transit_excess_ns: Summary::of_u64(&[2_000_000; 12]),
            gaps_filled: 12,
            gaps_lost: 340,
            gaps_open_at_end: 3,
            gaps_beyond_horizon: 7,
            late_beyond_horizon: 5,
        }
    }

    #[test]
    fn every_uplink_datagram_round_trips() {
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

        for accepted in [true, false] {
            let rdy = Ready {
                run_nonce: u64::MAX,
                rung: 4,
                accepted,
            };
            assert_eq!(Ready::decode(&rdy.encode()), Some(rdy));
        }

        let dh = DataHeader {
            run_nonce: u64::MAX,
            rung: 4,
            seq: 123_456,
            send_unix_ns: 1_700_000_000_000_000_000,
        };
        let mut buf = vec![0u8; 1200];
        dh.write_into(&mut buf);
        assert_eq!(DataHeader::decode(&buf), Some(dh));
    }

    /// The receiver's whole ledger, distributions included, has to survive the
    /// crossing — it is the only account of an upload that is not the sender's
    /// own opinion of itself.
    #[test]
    fn the_receivers_report_round_trips_with_its_distributions_intact() {
        let r = Report {
            run_nonce: 0x0102_0304_0506_0708,
            rung: 2,
            received_datagrams: 104_000,
            received_bytes: 124_800_000,
            first_datagram_bytes: 1200,
            reordered_datagrams: 12,
            duplicate_datagrams: 4,
            observed_window_ns: 5_000_000_000,
            reorder: demo_profile(),
        };
        let back = Report::decode(&r.encode()).expect("a report must round trip");
        assert_eq!(back, r);
        // Spot-check the distribution rather than trusting the equality alone:
        // a codec that zeroed every double would still compare equal against a
        // zeroed expectation, and these are the numbers a tolerance is sized on.
        assert_eq!(back.reorder.distance.p50, 6.0);
        assert_eq!(back.reorder.distance.max, 12.0);
        assert_eq!(back.reorder.displacement_ns.p99, 1_000_000.0);
        assert_eq!(back.reorder.transit_excess_ns.mean, 2_000_000.0);
        assert_eq!(back.reorder.distance.count, 12);
        assert_eq!(back.reorder.gaps_beyond_horizon, 7);
        assert_eq!(back.reorder.late_beyond_horizon, 5);
    }

    /// An empty distribution must stay empty. Zeroed percentiles with a
    /// non-zero count would read as "reordered by nothing", which is the
    /// opposite of what an unmeasured tail means.
    #[test]
    fn an_unmeasured_profile_survives_as_unmeasured() {
        let r = Report {
            run_nonce: 1,
            rung: 0,
            received_datagrams: 0,
            received_bytes: 0,
            first_datagram_bytes: 0,
            reordered_datagrams: 0,
            duplicate_datagrams: 0,
            observed_window_ns: 0,
            reorder: ReorderProfile::default(),
        };
        let back = Report::decode(&r.encode()).expect("round trip");
        assert_eq!(back.reorder, ReorderProfile::default());
        assert_eq!(back.reorder.distance.count, 0);
        assert_eq!(back.reorder.horizon, 0);
    }

    /// A double read off a public port can be any bit pattern, and `NaN` has no
    /// JSON encoding — the sample sink would replace the whole rung with a
    /// serialisation error. One corrupt field must cost one field.
    #[test]
    fn a_non_finite_double_on_the_wire_is_refused_rather_than_recorded() {
        let mut bytes = Report {
            run_nonce: 1,
            rung: 0,
            received_datagrams: 1,
            received_bytes: 1200,
            first_datagram_bytes: 1200,
            reordered_datagrams: 0,
            duplicate_datagrams: 0,
            observed_window_ns: 1,
            reorder: demo_profile(),
        }
        .encode();
        // The first double of the first distribution: `distance.min`.
        let at = 66 + 16 + 8;
        bytes[at..at + 8].copy_from_slice(&f64::NAN.to_bits().to_be_bytes());
        let back = Report::decode(&bytes).expect("decode");
        assert_eq!(back.reorder.distance.min, 0.0);
        assert!(back.reorder.distance.min.is_finite());
        // And the fields either side of it are untouched, so the guard is a
        // filter rather than a blanket.
        assert_eq!(back.reorder.distance.max, 12.0);
        assert_eq!(back.reorder.distance.count, 12);

        let inf = 66 + 16 + 8 + 8;
        bytes[inf..inf + 8].copy_from_slice(&f64::INFINITY.to_bits().to_be_bytes());
        let back = Report::decode(&bytes).expect("decode");
        assert_eq!(back.reorder.distance.max, 0.0);
        assert!(serde_json::to_string(&back.reorder).is_ok());
    }

    /// The two ladders describe a rung in one vocabulary. If they ever drift,
    /// the uplink and downlink rungs of a run stop being comparable and nothing
    /// else in the artifact would say so.
    #[test]
    fn the_two_ladders_ask_for_a_rung_in_the_same_words() {
        let up = Request {
            run_nonce: 0x1122_3344_5566_7788,
            cookie: [3u8; COOKIE_LEN],
            rung: 5,
            offered_kbps: 20_000,
            duration_ms: 10_000,
            payload_len: 1200,
        };
        let down = downlink::Request {
            run_nonce: up.run_nonce,
            cookie: up.cookie,
            rung: up.rung,
            offered_kbps: up.offered_kbps,
            duration_ms: up.duration_ms,
            payload_len: up.payload_len,
        };
        assert_eq!(REQUEST_LEN, downlink::REQUEST_LEN);
        assert_eq!(CHALLENGE_LEN, downlink::CHALLENGE_LEN);
        assert_eq!(
            up.encode()[8..],
            down.encode()[8..],
            "only the magic may differ"
        );
        assert_ne!(up.encode()[0..8], down.encode()[0..8]);
    }

    /// Three controls now sit on three public ports. A datagram of one must be
    /// unreadable by the others, or a burst counted in the wrong ledger reports
    /// a transfer that never happened.
    #[test]
    fn no_control_can_read_another_controls_datagrams() {
        let mut up = vec![0u8; downlink::DEFAULT_PAYLOAD];
        DataHeader {
            run_nonce: 1,
            rung: 0,
            seq: 7,
            send_unix_ns: 5,
        }
        .write_into(&mut up);
        assert_eq!(downlink::DataHeader::decode(&up), None);
        assert_eq!(downlink::EchoHeader::decode(&up), None);
        assert_eq!(downlink::Report::decode(&up), None);
        assert_eq!(Report::decode(&up), None);
        assert_eq!(Request::decode(&up), None);
        assert_eq!(Challenge::decode(&up), None);
        assert_eq!(Ready::decode(&up), None);

        let mut down = vec![0u8; downlink::DEFAULT_PAYLOAD];
        downlink::DataHeader {
            run_nonce: 1,
            rung: 0,
            seq: 7,
            send_unix_ns: 5,
        }
        .write_into(&mut down);
        assert_eq!(DataHeader::decode(&down), None);

        let mut echo = vec![0u8; downlink::DEFAULT_PAYLOAD];
        downlink::EchoHeader {
            run_nonce: 1,
            rung: 0,
            seq: 7,
            send_ns: 5,
        }
        .write_into(&mut echo);
        assert_eq!(DataHeader::decode(&echo), None);

        // And in the other direction: the downstream source must not answer an
        // uplink request, which is what would happen if the magics collided.
        let req = Request {
            run_nonce: 1,
            cookie: [1; COOKIE_LEN],
            rung: 0,
            offered_kbps: 1_000,
            duration_ms: 100,
            payload_len: 1200,
        }
        .encode();
        assert_eq!(downlink::Request::decode(&req), None);
    }

    /// These listeners sit on public ports. Anything unrecognised must decode
    /// to nothing rather than being half-parsed.
    #[test]
    fn foreign_and_truncated_datagrams_decode_to_nothing() {
        assert_eq!(Request::decode(&[]), None);
        assert_eq!(Request::decode(&[0u8; REQUEST_LEN]), None);
        assert_eq!(Request::decode(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(Challenge::decode(&[0u8; CHALLENGE_LEN]), None);
        assert_eq!(Ready::decode(&[0u8; READY_LEN]), None);
        assert_eq!(DataHeader::decode(&[0u8; DATA_HEADER_LEN]), None);
        assert_eq!(Report::decode(&[0u8; REPORT_LEN]), None);

        // Right magic, one byte short — every kind.
        let req = Request {
            run_nonce: 1,
            cookie: [0; COOKIE_LEN],
            rung: 0,
            offered_kbps: 1,
            duration_ms: 1,
            payload_len: 1200,
        }
        .encode();
        assert_eq!(Request::decode(&req[..REQUEST_LEN - 1]), None);
        let ch = Challenge {
            run_nonce: 1,
            cookie: [1; COOKIE_LEN],
        }
        .encode();
        assert_eq!(Challenge::decode(&ch[..CHALLENGE_LEN - 1]), None);
        let rdy = Ready {
            run_nonce: 1,
            rung: 0,
            accepted: true,
        }
        .encode();
        assert_eq!(Ready::decode(&rdy[..READY_LEN - 1]), None);
        let rep = Report {
            run_nonce: 1,
            rung: 0,
            received_datagrams: 1,
            received_bytes: 1,
            first_datagram_bytes: 1,
            reordered_datagrams: 0,
            duplicate_datagrams: 0,
            observed_window_ns: 1,
            reorder: demo_profile(),
        }
        .encode();
        assert_eq!(Report::decode(&rep[..REPORT_LEN - 1]), None);
        let mut short = vec![0u8; DATA_HEADER_LEN - 1];
        DataHeader {
            run_nonce: 1,
            rung: 0,
            seq: 1,
            send_unix_ns: 1,
        }
        .write_into(&mut short);
        assert_eq!(DataHeader::decode(&short), None);
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
}
