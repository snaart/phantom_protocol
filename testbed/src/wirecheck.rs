//! Whether the session's application bytes reach the wire — and, just as
//! importantly, which parts of that question a capture cannot reach at all.
//!
//! The check has three halves and they answer different things.
//!
//! **What a capture settles.** Take a packet capture while driving a session
//! whose payloads this probe generated itself, then search the captured bytes
//! for those exact payloads. Nothing found means the application's bytes are
//! not on the wire in the clear.
//!
//! **Why that is worth nothing on its own.** A search that finds nothing is
//! indistinguishable from a search that cannot find anything — a wrong
//! interface, an empty file, a decoder that silently gave up. So the same pass
//! also looks for something that *must* be there: the build's
//! `PROTOCOL_VARIANT` tag, which rides in the `ClientHello` in the clear
//! because the handshake is signed rather than encrypted. If the negative
//! search comes back empty and the positive control also comes back empty, the
//! run **failed** — it demonstrated nothing. [`Verdict`] says so in those
//! terms rather than reporting a pass.
//!
//! **What a capture cannot settle.** Nothing here is evidence about the
//! `ENCRYPTED` flag. Header protection masks all fifteen header bytes on the
//! wire, so an observer without the session's header-protection key cannot read
//! the flag field at all — no capture, however clean, can show that every
//! post-handshake packet carries it. That question is answered from the source,
//! and [`ENCRYPTED_FLAG_STATEMENT`] says exactly where the answer comes from
//! and where it is and is not pinned by a test. It travels into the artifact
//! with the numbers so a reader cannot mistake one for the other.
//!
//! Entropy is reported for the same reason it is reported carefully: it is
//! evidence that the payload is not structured, not proof that it is
//! encrypted. A forty-byte acknowledgement cannot exceed log2(40) ≈ 5.3 bits
//! per byte no matter what produced it, so a raw median over mixed lengths
//! reads as a finding when it is arithmetic. The distribution is therefore
//! reported twice: raw bits per byte over payloads long enough to reach the
//! eight-bit ceiling, and as a fraction of each payload's own ceiling over all
//! of them.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::stats::Summary;

/// Payload length at which Shannon entropy can reach 8.0 bits per byte.
///
/// Below 256 distinct byte values the empirical distribution simply has fewer
/// symbols to spread over, so its entropy is capped by `log2(len)` for reasons
/// that have nothing to do with cryptography.
pub const FULL_SCALE_LEN: usize = 256;

/// Payloads shorter than this carry no distributional information worth
/// summarising — a one-byte payload is at its ceiling by definition.
const TRIVIAL_LEN: usize = 2;

/// Ceiling on how much capture the analysis will read into memory.
///
/// The filter restricts the capture to one host and one port pair, so a run
/// produces a fraction of this. The bound exists so a mistake in the filter
/// costs a truncated analysis and a recorded note rather than the probe's
/// address space.
pub const MAX_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;

/// Largest single captured frame the reader will accept before treating the
/// file as corrupt. Well past any jumbo frame; small enough that a garbage
/// length field cannot ask for an allocation.
const MAX_FRAME_BYTES: u32 = 262_144;

// ── Needles ─────────────────────────────────────────────────────────────────

/// What finding a given byte string would mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Polarity {
    /// Application bytes this probe generated. A hit is a plaintext leak.
    MustNotAppear,
    /// The positive control. **Not finding it fails the run**, because a search
    /// that cannot find what is known to be there has not shown it can find
    /// anything.
    MustAppear,
    /// Recorded either way. Used for material that is open by design and whose
    /// presence or absence is a fact worth keeping rather than a verdict.
    Observed,
}

/// One byte string to look for, and what its presence would mean.
#[derive(Debug, Clone)]
pub struct Needle {
    pub label: String,
    pub bytes: Vec<u8>,
    pub polarity: Polarity,
}

impl Needle {
    pub fn new(label: impl Into<String>, bytes: Vec<u8>, polarity: Polarity) -> Self {
        Self {
            label: label.into(),
            bytes,
            polarity,
        }
    }
}

/// Application payload carried by each probed message.
///
/// Sized so that the whole framed message — this payload plus
/// [`PROBE_FRAMING_BYTES`] — fits in one `MAX_APP_CHUNK`. That matters because
/// `PhantomSession::send()` splits anything larger, and a payload split across
/// two packets would put the needle across a frame boundary where a
/// whole-frame search cannot see it. The check would then come back clean for
/// an arithmetic reason.
pub const PROBE_PAYLOAD_BYTES: usize = 1024;

/// Bytes the testbed adds around that payload on the wider of the two
/// directions: a 4-byte length prefix, a verb byte, and the four 8-byte
/// timestamps an `ECHO_REPLY` carries.
pub const PROBE_FRAMING_BYTES: usize = 4 + 1 + 8 * 4;

// The chunk arithmetic, enforced at build time rather than left to a test: if
// the framed message outgrew one chunk the payload would be split across
// packets, and a whole-frame search would come back clean for a reason that has
// nothing to do with encryption.
const _: () = assert!(
    PROBE_PAYLOAD_BYTES + PROBE_FRAMING_BYTES <= phantom_protocol::transport::mtu::MAX_APP_CHUNK
);
// And not so small that the probe stops resembling real traffic: a payload
// under the full-scale length would have no entropy headroom to report.
const _: () = assert!(PROBE_PAYLOAD_BYTES >= FULL_SCALE_LEN * 2);

/// The ASCII marker that leads every probed payload.
///
/// A run nonce keeps two runs from sharing needles, and the sequence number
/// keeps each message's marker distinct so a hit names the message. It is
/// deliberately printable: a protocol that leaked structured application data
/// would leak it as text, and a searcher looking only for high-entropy blobs
/// would be looking for the wrong thing.
pub fn probe_marker(nonce: u64, seq: usize) -> String {
    format!("PHANTOM-WIRECHECK-{nonce:016x}-{seq:04}")
}

/// The needle set for one run: the positive control first, then two needles per
/// message the probe sent.
///
/// Two per message rather than one because they fail differently. The whole
/// payload is the strongest statement — those exact 1024 bytes are nowhere on
/// the wire — but it is also the most fragile, since any re-framing between the
/// application and the link would break it into pieces no single frame
/// contains. The leading marker is short enough to survive that. A leak has to
/// evade both.
pub fn needles_for(messages: &[(String, Vec<u8>)], control: &[u8]) -> Vec<Needle> {
    let mut out = Vec::with_capacity(1 + messages.len() * 2);
    out.push(Needle::new(
        "protocol_variant",
        control.to_vec(),
        Polarity::MustAppear,
    ));
    for (marker, payload) in messages {
        out.push(Needle::new(
            format!("payload:{marker}"),
            payload.clone(),
            Polarity::MustNotAppear,
        ));
        out.push(Needle::new(
            format!("marker:{marker}"),
            marker.as_bytes().to_vec(),
            Polarity::MustNotAppear,
        ));
    }
    out
}

/// What the search found for one needle.
///
/// The hit counts are split by phase because *where* a string appears matters:
/// the positive control belongs in the handshake, and an application payload
/// belongs nowhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeedleResult {
    pub label: String,
    pub polarity: Polarity,
    /// Length of the string searched for. A one-byte needle would hit
    /// everything, so the length is part of reading the result.
    pub needle_bytes: usize,
    pub frames_hit: usize,
    pub hits_in_handshake: usize,
    pub hits_in_established: usize,
    /// Index of the first frame carrying it, for anyone re-opening the capture.
    pub first_frame: Option<usize>,
}

// ── Findings ────────────────────────────────────────────────────────────────

/// Which side of the session establishment a frame fell on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Captured before the session reported itself ready.
    Handshake,
    /// Captured after. These are the frames the negative search is about.
    Established,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The positive control was found and no application bytes were.
    Pass,
    /// Something the check exists to catch happened — including the case where
    /// the search found nothing at all and so proved nothing.
    Failed,
    /// No capture could be taken. Recorded with a reason, never silently.
    Skipped,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// Frames the decoder could not reach, grouped by why.
///
/// Reported rather than dropped: the negative search runs over whole frames and
/// so is unaffected, but the entropy distribution is computed from decoded
/// transport payloads only, and a reader needs to know what fraction of the
/// capture that was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndecodableCount {
    pub reason: String,
    pub frames: usize,
}

/// The entropy distribution over one phase's payloads.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EntropyBlock {
    /// Non-empty transport payloads seen in this phase.
    pub payloads: usize,
    /// Of those, how many are at least [`FULL_SCALE_LEN`] bytes and so *could*
    /// reach 8.0 bits per byte.
    pub full_scale_payloads: usize,
    /// Payloads under two bytes, excluded from the ratio distribution because a
    /// single byte is at its ceiling by definition.
    pub trivial_payloads: usize,
    /// Shannon entropy in bits per byte, over the full-scale payloads only.
    /// Empty when there were none — an absent distribution, not a zero one.
    pub bits_per_byte: Summary,
    /// Entropy as a fraction of what a payload of that exact length could
    /// reach. Defined for every non-trivial payload, so a short
    /// acknowledgement is comparable with a full-size data frame.
    pub ratio_of_ceiling: Summary,
    pub payload_bytes: Summary,
}

/// Everything the check established, and everything it did not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Findings {
    pub verdict: Verdict,
    /// Empty on a pass. On a failure or a skip, why — in the terms a reader
    /// needs, not a code.
    pub reasons: Vec<String>,

    pub capture_bytes: usize,
    pub link_type: u32,
    pub link_type_name: String,
    pub frames_total: usize,
    pub frames_decoded: usize,
    pub undecodable: Vec<UndecodableCount>,
    /// True when the capture file ended mid-record, which is the expected shape
    /// when the capture process is stopped rather than allowed to finish.
    pub capture_truncated: bool,

    pub handshake_frames: usize,
    pub established_frames: usize,

    pub needles: Vec<NeedleResult>,
    pub handshake_entropy: EntropyBlock,
    pub established_entropy: EntropyBlock,

    /// What this check says about the `ENCRYPTED` flag and where that answer
    /// comes from. Carried in the record so the distinction between what was
    /// measured and what was read out of the source travels with the data.
    pub encrypted_flag: Vec<String>,
}

impl Findings {
    /// A run where no capture could be taken.
    ///
    /// A skip is not a pass and is not an error: it is an absence with a stated
    /// cause, which is the only honest thing to record when the machine running
    /// the probe cannot capture.
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Skipped,
            reasons: vec![reason.into()],
            capture_bytes: 0,
            link_type: 0,
            link_type_name: String::new(),
            frames_total: 0,
            frames_decoded: 0,
            undecodable: Vec::new(),
            capture_truncated: false,
            handshake_frames: 0,
            established_frames: 0,
            needles: Vec::new(),
            handshake_entropy: EntropyBlock::default(),
            established_entropy: EntropyBlock::default(),
            encrypted_flag: encrypted_flag_statement(),
        }
    }
}

// ── The analysis ────────────────────────────────────────────────────────────

/// Read a classic-pcap capture and answer the two questions it can answer.
///
/// `established_unix_ns` splits the capture: frames stamped before it belong to
/// the handshake, frames at or after it to the established session. Both
/// stamps come from the same host's realtime clock — the capture process and
/// this probe run side by side — so the comparison is exact rather than
/// estimated.
///
/// The needle search runs over **whole captured frames**, link-layer bytes
/// included, not over the decoded payloads. That is deliberate and it is the
/// conservative choice: a bug in the decoders below could hide a payload from
/// the entropy distribution, but it cannot hide one from the search.
pub fn analyze(
    capture: &[u8],
    needles: &[Needle],
    established_unix_ns: u64,
) -> Result<Findings, PcapError> {
    let pcap = read_pcap(capture)?;

    let mut results: Vec<NeedleResult> = needles
        .iter()
        .map(|n| NeedleResult {
            label: n.label.clone(),
            polarity: n.polarity,
            needle_bytes: n.bytes.len(),
            frames_hit: 0,
            hits_in_handshake: 0,
            hits_in_established: 0,
            first_frame: None,
        })
        .collect();

    let mut undecodable: Vec<(&'static str, usize)> = Vec::new();
    let mut handshake_payloads: Vec<usize> = Vec::new();
    let mut established_payloads: Vec<usize> = Vec::new();
    let mut handshake_entropy: Vec<(usize, f64)> = Vec::new();
    let mut established_entropy: Vec<(usize, f64)> = Vec::new();
    let mut handshake_frames = 0usize;
    let mut established_frames = 0usize;
    let mut decoded = 0usize;

    for (idx, frame) in pcap.frames.iter().enumerate() {
        let phase = if frame.unix_ns < established_unix_ns {
            handshake_frames += 1;
            Phase::Handshake
        } else {
            established_frames += 1;
            Phase::Established
        };

        for (needle, result) in needles.iter().zip(results.iter_mut()) {
            if contains(frame.bytes, &needle.bytes).is_some() {
                result.frames_hit += 1;
                match phase {
                    Phase::Handshake => result.hits_in_handshake += 1,
                    Phase::Established => result.hits_in_established += 1,
                }
                if result.first_frame.is_none() {
                    result.first_frame = Some(idx);
                }
            }
        }

        match transport_payload(pcap.link_type, frame.bytes) {
            Ok(range) => {
                decoded += 1;
                let payload = &frame.bytes[range];
                if payload.is_empty() {
                    continue;
                }
                let h = shannon_bits_per_byte(payload);
                match phase {
                    Phase::Handshake => {
                        handshake_payloads.push(payload.len());
                        handshake_entropy.push((payload.len(), h));
                    }
                    Phase::Established => {
                        established_payloads.push(payload.len());
                        established_entropy.push((payload.len(), h));
                    }
                }
            }
            Err(reason) => match undecodable.iter_mut().find(|(r, _)| *r == reason.label()) {
                Some((_, n)) => *n += 1,
                None => undecodable.push((reason.label(), 1)),
            },
        }
    }

    let mut findings = Findings {
        verdict: Verdict::Pass,
        reasons: Vec::new(),
        capture_bytes: capture.len(),
        link_type: pcap.link_type,
        link_type_name: link_type_name(pcap.link_type).to_string(),
        frames_total: pcap.frames.len(),
        frames_decoded: decoded,
        undecodable: undecodable
            .into_iter()
            .map(|(reason, frames)| UndecodableCount {
                reason: reason.to_string(),
                frames,
            })
            .collect(),
        capture_truncated: pcap.truncated,
        handshake_frames,
        established_frames,
        needles: results,
        handshake_entropy: entropy_block(&handshake_entropy, &handshake_payloads),
        established_entropy: entropy_block(&established_entropy, &established_payloads),
        encrypted_flag: encrypted_flag_statement(),
    };

    findings.reasons = judge(&findings);
    findings.verdict = if findings.reasons.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Failed
    };
    Ok(findings)
}

/// Everything wrong with a completed capture, in the order a reader should hear
/// it — the reasons the search proved nothing come before the leaks it found,
/// because the second is meaningless without the first.
fn judge(f: &Findings) -> Vec<String> {
    let mut reasons = Vec::new();

    for n in f
        .needles
        .iter()
        .filter(|n| n.polarity == Polarity::MustAppear)
    {
        if n.frames_hit == 0 {
            reasons.push(format!(
                "the positive control `{}` ({} B) was not found anywhere in {} captured frames. \
                 The search has therefore not been shown capable of finding anything, and the \
                 absence of application payloads below is worth nothing. This is a failed run, \
                 not a passing one",
                n.label, n.needle_bytes, f.frames_total
            ));
        }
    }

    if f.frames_total == 0 {
        reasons.push(
            "the capture contains no frames at all — check the interface and the filter"
                .to_string(),
        );
    } else if f.established_frames == 0 {
        reasons.push(format!(
            "no frame was captured after the session reported itself established, so the search \
             covered only the handshake. \"No application bytes on the wire\" is vacuous when no \
             application bytes were sent during the capture ({} handshake frames)",
            f.handshake_frames
        ));
    }

    for n in f
        .needles
        .iter()
        .filter(|n| n.polarity == Polarity::MustNotAppear)
    {
        if n.frames_hit > 0 {
            reasons.push(format!(
                "application payload `{}` ({} B) appears in {} captured frame(s) \
                 ({} during the handshake, {} after establishment), first at frame {}. \
                 This is plaintext on the wire",
                n.label,
                n.needle_bytes,
                n.frames_hit,
                n.hits_in_handshake,
                n.hits_in_established,
                n.first_frame.map(|i| i.to_string()).unwrap_or_default(),
            ));
        }
    }

    reasons
}

/// Summarise one phase's payload entropy.
///
/// `samples` pairs each payload's length with its Shannon entropy; `lengths` is
/// the same set of lengths, kept separately so the length distribution reports
/// every payload including the trivially short ones.
fn entropy_block(samples: &[(usize, f64)], lengths: &[usize]) -> EntropyBlock {
    let full_scale: Vec<f64> = samples
        .iter()
        .filter(|(len, _)| *len >= FULL_SCALE_LEN)
        .map(|(_, h)| *h)
        .collect();
    let ratios: Vec<f64> = samples
        .iter()
        .filter(|(len, _)| *len >= TRIVIAL_LEN)
        .map(|(len, h)| h / entropy_ceiling(*len))
        .collect();
    EntropyBlock {
        payloads: samples.len(),
        full_scale_payloads: full_scale.len(),
        trivial_payloads: samples.iter().filter(|(len, _)| *len < TRIVIAL_LEN).count(),
        bits_per_byte: Summary::of(&full_scale),
        ratio_of_ceiling: Summary::of(&ratios),
        payload_bytes: Summary::of(&lengths.iter().map(|&l| l as f64).collect::<Vec<f64>>()),
    }
}

/// Shannon entropy of a byte string, in bits per byte.
pub fn shannon_bits_per_byte(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// The largest entropy a byte string of this length can have, bits per byte.
///
/// With `len` bytes there are at most `min(len, 256)` distinct symbols, and the
/// entropy is maximal when they are equally frequent. A payload that reaches
/// this bound is as uniform as a payload of its length can be, which is the
/// only statement entropy can make about a short one.
pub fn entropy_ceiling(len: usize) -> f64 {
    if len < TRIVIAL_LEN {
        return 0.0;
    }
    (len.min(256) as f64).log2()
}

/// First offset at which `needle` occurs in `haystack`.
///
/// A plain scan with a first-byte guard. The captures this runs over are a few
/// hundred frames, and a dependency-free implementation keeps the analysis
/// something a reader can check by eye.
fn contains(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let first = needle[0];
    let last = haystack.len() - needle.len();
    (0..=last).find(|&i| haystack[i] == first && &haystack[i..i + needle.len()] == needle)
}

// ── What the capture cannot answer ──────────────────────────────────────────

/// The `ENCRYPTED`-flag statement, verbatim, as it goes into the artifact.
///
/// This is the part of the check that is not a measurement, and it is written
/// out in full rather than summarised because the whole point is that a reader
/// must not mistake it for one. Every claim in it names the file it was read
/// from.
pub fn encrypted_flag_statement() -> Vec<String> {
    ENCRYPTED_FLAG_STATEMENT
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// See [`encrypted_flag_statement`].
pub const ENCRYPTED_FLAG_STATEMENT: &[&str] = &[
    "Answered from the source, not from the capture. Security invariant 2 requires every \
     post-handshake packet to carry the ENCRYPTED flag. That flag lives in the 15-byte packet \
     header, and header protection masks the header from byte 0, so an observer without the \
     session's header-protection key cannot read it. No capture can confirm or refute it, and \
     nothing else in this record is evidence about it.",
    "The mechanism, in core/src/api/session.rs: the send path ORs PacketFlags::ENCRYPTED into \
     every application frame's flags before sealing, and the receive path drops any \
     post-handshake packet that arrives without it — including an empty-payload one, which \
     closes the forged-standalone-FIN case.",
    "Where it is pinned: the in-lib tests in core/src/api/session.rs. \
     `v2_recv_drops_unencrypted_non_empty_post_handshake_payload` drives handle_packet with an \
     unencrypted, non-empty packet and asserts nothing is delivered; \
     `forged_unencrypted_fin_does_not_close_a_stream` does the same for the empty-payload FIN. \
     The send-side property is asserted by the `decrypt_incoming` helper the handshake \
     round-trip tests use, which fails if a frame arrives without the flag. All of these run \
     under `cargo test --lib`.",
    "Where it is NOT pinned, and this is a gap worth knowing about: \
     core/tests/security_invariants.rs — the always-on suite documented as pinning the numbered \
     invariants — contains no test of either gate. It exercises the AEAD layer directly and \
     never calls handle_packet. What it does hold is the neighbouring property: the header flags \
     are covered by the AEAD associated data, so ENCRYPTED cannot be stripped from a genuine \
     packet without breaking the tag (tampered_header_is_rejected_via_aad, padded_flag_is_aead_bound). \
     That is a different statement from \"an unencrypted packet is dropped\", and a reader who \
     goes to that file for invariant 2 will not find the gate there.",
    "There is no run-time counter to fall back on either: the drop is recorded through \
     Observability::record_unencrypted_dropped, which is an OpenTelemetry instrument only. It \
     compiles to a no-op without the telemetry-otel feature and has no field in \
     MetricsSnapshotFfi, so neither this probe nor an operator on a default build can observe \
     the gate firing.",
];

// ── pcap reading ────────────────────────────────────────────────────────────

/// One captured frame: the link-layer bytes as they were seen, and when.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    /// Capture timestamp, nanoseconds since the Unix epoch.
    pub unix_ns: u64,
    pub bytes: &'a [u8],
}

/// A parsed classic-pcap file.
#[derive(Debug)]
pub struct Pcap<'a> {
    pub link_type: u32,
    pub frames: Vec<Frame<'a>>,
    /// The file ended mid-record. Expected when the capture process is stopped
    /// rather than allowed to close its own file, so it is reported rather than
    /// treated as corruption.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapError {
    /// Fewer bytes than a pcap file header. Usually means the capture process
    /// never started writing.
    TooShort(usize),
    /// The pcapng magic. tcpdump writes classic pcap; something else wrote this.
    IsPcapng,
    Unrecognised(u32),
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(n) => write!(
                f,
                "capture is {n} B, shorter than a pcap file header — the capture process wrote nothing"
            ),
            Self::IsPcapng => write!(
                f,
                "capture is pcapng, not classic pcap; this reader handles the classic format tcpdump writes"
            ),
            Self::Unrecognised(m) => write!(f, "unrecognised pcap magic 0x{m:08x}"),
        }
    }
}

impl std::error::Error for PcapError {}

/// Parse a classic-pcap byte stream.
///
/// Four magics are accepted: little- and big-endian, each in the original
/// microsecond form and the later nanosecond one. Anything else is named
/// rather than guessed at.
pub fn read_pcap(bytes: &[u8]) -> Result<Pcap<'_>, PcapError> {
    if bytes.len() < 24 {
        return Err(PcapError::TooShort(bytes.len()));
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (big_endian, nanos) = match magic {
        0xa1b2_c3d4 => (false, false),
        0xa1b2_3c4d => (false, true),
        0xd4c3_b2a1 => (true, false),
        0x4d3c_b2a1 => (true, true),
        0x0a0d_0d0a => return Err(PcapError::IsPcapng),
        other => return Err(PcapError::Unrecognised(other)),
    };
    let rd32 = |b: &[u8]| -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if big_endian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };

    let link_type = rd32(&bytes[20..24]);
    let mut frames = Vec::new();
    let mut truncated = false;
    let mut pos = 24usize;

    while pos < bytes.len() {
        if bytes.len() - pos < 16 {
            truncated = true;
            break;
        }
        let ts_sec = rd32(&bytes[pos..pos + 4]) as u64;
        let ts_frac = rd32(&bytes[pos + 4..pos + 8]) as u64;
        let incl_len = rd32(&bytes[pos + 8..pos + 12]);
        pos += 16;

        if incl_len > MAX_FRAME_BYTES {
            // A length no capture would produce means the file is no longer
            // being read at a record boundary. Stop and say so rather than
            // sliding along and reporting invented frames.
            truncated = true;
            break;
        }
        let len = incl_len as usize;
        if bytes.len() - pos < len {
            truncated = true;
            break;
        }
        let unix_ns = ts_sec
            .saturating_mul(1_000_000_000)
            .saturating_add(if nanos { ts_frac } else { ts_frac * 1_000 });
        frames.push(Frame {
            unix_ns,
            bytes: &bytes[pos..pos + len],
        });
        pos += len;
    }

    Ok(Pcap {
        link_type,
        frames,
        truncated,
    })
}

pub fn link_type_name(link_type: u32) -> &'static str {
    match link_type {
        0 => "NULL",
        1 => "EN10MB",
        12 | 14 | 101 => "RAW",
        108 => "LOOP",
        113 => "LINUX_SLL",
        276 => "LINUX_SLL2",
        _ => "unsupported",
    }
}

// ── Frame decoding ──────────────────────────────────────────────────────────

/// Why a frame yielded no transport payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undecodable {
    UnsupportedLinkType,
    ShortFrame,
    NotIp,
    UnsupportedIpVersion,
    UnsupportedIpProtocol,
}

impl Undecodable {
    pub fn label(self) -> &'static str {
        match self {
            Self::UnsupportedLinkType => "unsupported link type",
            Self::ShortFrame => "frame shorter than its own headers",
            Self::NotIp => "not IP",
            Self::UnsupportedIpVersion => "unsupported IP version",
            Self::UnsupportedIpProtocol => "not TCP or UDP",
        }
    }
}

/// The range of `frame` holding the TCP or UDP payload.
pub fn transport_payload(link_type: u32, frame: &[u8]) -> Result<Range<usize>, Undecodable> {
    let (offset, ethertype) = strip_link(link_type, frame)?;
    let (proto, ip_payload) = strip_ip(frame, offset, ethertype)?;
    strip_transport(frame, proto, ip_payload)
}

/// Skip the link-layer header, reporting the EtherType when the link layer
/// names one. `None` means the next header must be identified from the IP
/// version nibble itself.
fn strip_link(link_type: u32, frame: &[u8]) -> Result<(usize, Option<u16>), Undecodable> {
    match link_type {
        // BSD loopback: a four-byte address family in host byte order. Read it
        // both ways rather than guessing the capturing host's endianness.
        0 | 108 => {
            let hdr = frame.get(..4).ok_or(Undecodable::ShortFrame)?;
            let le = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
            let be = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
            // AF_INET is 2 everywhere; AF_INET6 is 24 on Darwin, 28 on FreeBSD,
            // 30 on NetBSD/OpenBSD, 10 on Linux.
            let ether = if le == 2 || be == 2 {
                Some(0x0800)
            } else if matches!(le, 10 | 24 | 28 | 30) || matches!(be, 10 | 24 | 28 | 30) {
                Some(0x86DD)
            } else {
                return Err(Undecodable::NotIp);
            };
            Ok((4, ether))
        }
        1 => {
            let mut off = 14usize;
            let hdr = frame.get(..off).ok_or(Undecodable::ShortFrame)?;
            let mut ether = u16::from_be_bytes([hdr[12], hdr[13]]);
            // VLAN tags stack; each one pushes the real EtherType four bytes on.
            let mut tags = 0;
            while matches!(ether, 0x8100 | 0x88A8 | 0x9100) && tags < 2 {
                let tag = frame.get(off..off + 4).ok_or(Undecodable::ShortFrame)?;
                ether = u16::from_be_bytes([tag[2], tag[3]]);
                off += 4;
                tags += 1;
            }
            Ok((off, Some(ether)))
        }
        12 | 14 | 101 => Ok((0, None)),
        113 => {
            let hdr = frame.get(..16).ok_or(Undecodable::ShortFrame)?;
            Ok((16, Some(u16::from_be_bytes([hdr[14], hdr[15]]))))
        }
        276 => {
            let hdr = frame.get(..20).ok_or(Undecodable::ShortFrame)?;
            Ok((20, Some(u16::from_be_bytes([hdr[0], hdr[1]]))))
        }
        _ => Err(Undecodable::UnsupportedLinkType),
    }
}

/// Skip the IP header, returning the transport protocol number and the offset
/// of its header.
fn strip_ip(
    frame: &[u8],
    offset: usize,
    ethertype: Option<u16>,
) -> Result<(u8, usize), Undecodable> {
    let first = *frame.get(offset).ok_or(Undecodable::ShortFrame)?;
    let version = match ethertype {
        Some(0x0800) => 4,
        Some(0x86DD) => 6,
        Some(_) => return Err(Undecodable::NotIp),
        None => first >> 4,
    };

    match version {
        4 => {
            let ihl = (first & 0x0F) as usize * 4;
            if ihl < 20 {
                return Err(Undecodable::ShortFrame);
            }
            let hdr = frame
                .get(offset..offset + ihl)
                .ok_or(Undecodable::ShortFrame)?;
            // A non-zero fragment offset means this frame carries no transport
            // header at all. Counted as undecodable rather than mis-parsed.
            let frag = u16::from_be_bytes([hdr[6], hdr[7]]) & 0x1FFF;
            if frag != 0 {
                return Err(Undecodable::UnsupportedIpProtocol);
            }
            Ok((hdr[9], offset + ihl))
        }
        6 => {
            let hdr = frame
                .get(offset..offset + 40)
                .ok_or(Undecodable::ShortFrame)?;
            let mut next = hdr[6];
            let mut pos = offset + 40;
            // Walk the extension chain. Every one of these is
            // [next header][length in 8-octet units, header excluded].
            for _ in 0..8 {
                match next {
                    0 | 43 | 60 => {
                        let ext = frame.get(pos..pos + 2).ok_or(Undecodable::ShortFrame)?;
                        next = ext[0];
                        pos += (ext[1] as usize + 1) * 8;
                    }
                    44 => {
                        let ext = frame.get(pos..pos + 8).ok_or(Undecodable::ShortFrame)?;
                        next = ext[0];
                        pos += 8;
                    }
                    _ => return Ok((next, pos)),
                }
            }
            Err(Undecodable::UnsupportedIpProtocol)
        }
        _ => Err(Undecodable::UnsupportedIpVersion),
    }
}

fn strip_transport(frame: &[u8], proto: u8, offset: usize) -> Result<Range<usize>, Undecodable> {
    match proto {
        // UDP: an eight-byte header whose length field covers header and
        // payload. The captured frame can be shorter than the field claims —
        // Ethernet padding aside, a snaplen cut looks exactly like this — so
        // the range is clamped to what was actually captured.
        17 => {
            let hdr = frame
                .get(offset..offset + 8)
                .ok_or(Undecodable::ShortFrame)?;
            let declared = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
            let start = offset + 8;
            let end = if declared >= 8 {
                (offset + declared).min(frame.len())
            } else {
                frame.len()
            };
            Ok(start..end.max(start))
        }
        6 => {
            let hdr = frame
                .get(offset..offset + 20)
                .ok_or(Undecodable::ShortFrame)?;
            let data_offset = (hdr[12] >> 4) as usize * 4;
            if data_offset < 20 {
                return Err(Undecodable::ShortFrame);
            }
            let start = offset + data_offset;
            if start > frame.len() {
                return Err(Undecodable::ShortFrame);
            }
            Ok(start..frame.len())
        }
        _ => Err(Undecodable::UnsupportedIpProtocol),
    }
}

// ── Taking the capture ──────────────────────────────────────────────────────

/// Where and what to capture.
#[derive(Debug, Clone)]
pub struct CaptureRequest {
    /// Interface name handed to `tcpdump -i`. `any` works on Linux and does not
    /// exist on macOS, which is one of the ordinary reasons a run skips.
    pub interface: String,
    /// BPF expression, from [`filter_for`].
    pub filter: String,
    /// Where the capture is written. Kept after the run: it is the raw evidence
    /// behind every number derived from it.
    pub path: PathBuf,
}

/// The BPF filter for one leg's traffic.
///
/// Anchored on the peer address so nothing else on the host enters the file,
/// and left open across both transports because a leg's port number is unique
/// to it and naming only one would silently miss a leg that moved.
pub fn filter_for(peer: &str, port: u16) -> String {
    format!("host {peer} and (tcp port {port} or udp port {port})")
}

/// The exact `tcpdump` invocation, as a list, so a reader can reproduce it by
/// hand and a test can pin the flags that matter.
///
/// `-U` is the load-bearing one: it flushes every packet to the file as it
/// arrives, so stopping the process cannot lose the capture's tail. `-s 0`
/// takes whole frames — a snaplen cut would truncate exactly the payload the
/// search is about. `-n` keeps tcpdump from resolving names, which would put
/// DNS traffic on the wire in the middle of the measurement.
pub fn tcpdump_args(req: &CaptureRequest) -> Vec<String> {
    vec![
        "-i".to_string(),
        req.interface.clone(),
        "-n".to_string(),
        "-s".to_string(),
        "0".to_string(),
        "-U".to_string(),
        "-w".to_string(),
        req.path.display().to_string(),
        req.filter.clone(),
    ]
}

/// Turn what tcpdump said on the way out into a reason an operator can act on.
///
/// The permission case gets its own sentence because it is by far the most
/// common and because the remedy differs by platform; everything else is passed
/// through verbatim rather than being flattened into "capture failed".
pub fn diagnose(stderr: &str) -> String {
    let trimmed = stderr.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("you don't have permission")
        || lower.contains("bpf")
    {
        return format!(
            "capturing needs elevated rights on this host and the probe has none ({}). \
             Grant them and re-run just this scenario: on Linux \
             `sudo setcap cap_net_raw,cap_net_admin+eip $(command -v tcpdump)`, on macOS run \
             the probe under sudo",
            said(trimmed)
        );
    }
    if trimmed.is_empty() {
        return "tcpdump exited before the capture began and said nothing".to_string();
    }
    format!("tcpdump exited before the capture began: {}", said(trimmed))
}

/// tcpdump's own first substantive line, with its self-naming prefix left in
/// place if it has one and added if it does not — so the quoted text is always
/// attributable and never says "tcpdump: tcpdump:".
fn said(stderr: &str) -> String {
    let line = first_line(stderr);
    if line.starts_with("tcpdump") {
        line.to_string()
    } else {
        format!("tcpdump: {line}")
    }
}

fn first_line(s: &str) -> &str {
    s.lines().find(|l| !l.trim().is_empty()).unwrap_or(s).trim()
}

/// A running capture.
pub struct Capture {
    child: tokio::process::Child,
    path: PathBuf,
    stderr: Arc<Mutex<String>>,
    /// The command line, recorded so the artifact says how the evidence was
    /// produced.
    pub command: String,
}

impl Capture {
    /// How long to wait for tcpdump to open its file before giving up.
    const READY_TIMEOUT: Duration = Duration::from_secs(5);

    /// Start capturing, or return the reason this host cannot.
    ///
    /// The error is the skip reason, ready to record: capture is a privileged
    /// operation and a probe that cannot perform it must say so rather than
    /// quietly reporting a check it never ran.
    pub async fn start(req: &CaptureRequest) -> Result<Self, String> {
        if let Some(parent) = req.path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Err(format!(
                    "cannot create the capture directory {}: {e}",
                    parent.display()
                ));
            }
        }
        // A stale file from an earlier run would be appended to, and the
        // readiness check below would pass on its header instead of the new
        // one's.
        let _ = std::fs::remove_file(&req.path);

        let args = tcpdump_args(req);
        let command = format!("tcpdump {}", args.join(" "));
        let mut child = match tokio::process::Command::new("tcpdump")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(
                    "tcpdump is not installed on this host, so no capture can be taken".to_string(),
                )
            }
            Err(e) => return Err(format!("could not start tcpdump: {e}")),
        };

        // Drain stderr continuously. tcpdump reports its refusals there and
        // exits; without a reader the pipe could fill and the diagnosis would
        // be a hang instead of a sentence.
        let stderr_buf = Arc::new(Mutex::new(String::new()));
        if let Some(mut pipe) = child.stderr.take() {
            let sink = stderr_buf.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf).await;
                buf.truncate(8 * 1024);
                if let Ok(mut g) = sink.lock() {
                    g.push_str(&String::from_utf8_lossy(&buf));
                }
            });
        }

        let mut capture = Self {
            child,
            path: req.path.clone(),
            stderr: stderr_buf,
            command,
        };

        // Ready means "the file header is on disk". Waiting on tcpdump's own
        // "listening on ..." line would depend on its wording and its locale;
        // the 24-byte header is the thing the reader actually needs.
        let deadline = Instant::now() + Self::READY_TIMEOUT;
        loop {
            if std::fs::metadata(&req.path).map(|m| m.len()).unwrap_or(0) >= 24 {
                // Let the capture settle before the first packet is sent: the
                // header lands slightly before the filter is attached.
                tokio::time::sleep(Duration::from_millis(250)).await;
                return Ok(capture);
            }
            // tcpdump refuses by writing a line and exiting, so asking here
            // turns the common failure into an answer in milliseconds instead
            // of one at the readiness deadline. A `try_wait` error means the
            // child is unreachable, which is equally terminal.
            if !matches!(capture.child.try_wait(), Ok(None)) {
                // The stderr reader is a separate task; give it a moment to
                // drain the pipe the child just closed, or the diagnosis would
                // be the empty string.
                tokio::time::sleep(Duration::from_millis(100)).await;
                let why = diagnose(&capture.stderr_text());
                capture.discard();
                return Err(why);
            }
            if Instant::now() >= deadline {
                let said = capture.stderr_text();
                capture.discard();
                return Err(format!(
                    "tcpdump did not begin writing within {} s{}",
                    Self::READY_TIMEOUT.as_secs(),
                    if said.trim().is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", first_line(&said))
                    }
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn stderr_text(&self) -> String {
        self.stderr
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    /// Abandon a capture that never started. The process dies with the handle
    /// (`kill_on_drop`); the part-written file is of no use to anyone.
    fn discard(self) {
        let _ = std::fs::remove_file(&self.path);
    }

    /// Stop capturing and read what was written.
    ///
    /// Terminating the process rather than letting it finish is why `-U` is
    /// passed: every packet is already on disk when this runs.
    pub async fn finish(mut self) -> Result<Vec<u8>, String> {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;

        let len = match std::fs::metadata(&self.path) {
            Ok(m) => m.len(),
            Err(e) => {
                let said = self.stderr_text();
                return Err(format!(
                    "the capture file {} was never written ({e}){}",
                    self.path.display(),
                    if said.trim().is_empty() {
                        String::new()
                    } else {
                        format!(": {}", first_line(&said))
                    }
                ));
            }
        };
        let bytes = match read_capped(&self.path, MAX_CAPTURE_BYTES.min(len)) {
            Ok(b) => b,
            Err(e) => return Err(format!("cannot read {}: {e}", self.path.display())),
        };
        Ok(bytes)
    }

    /// Where the capture was written, so the artifact can name it.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn read_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(cap as usize);
    f.take(cap).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constructed captures ────────────────────────────────────────────────

    /// Build a classic-pcap byte stream from `(unix_ns, frame)` pairs.
    fn pcap_of(link_type: u32, frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65_535u32.to_le_bytes());
        out.extend_from_slice(&link_type.to_le_bytes());
        for (ns, f) in frames {
            out.extend_from_slice(&((ns / 1_000_000_000) as u32).to_le_bytes());
            out.extend_from_slice(&((ns % 1_000_000_000 / 1_000) as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    /// An Ethernet/IPv4/UDP frame carrying `payload`.
    fn udp4(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00;
        let total = 20 + 8 + payload.len();
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        f.extend_from_slice(&ip);
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&4243u16.to_be_bytes());
        udp[2..4].copy_from_slice(&40000u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&udp);
        f.extend_from_slice(payload);
        f
    }

    /// An Ethernet/IPv4/TCP frame carrying `payload`.
    fn tcp4(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes());
        ip[9] = 6;
        f.extend_from_slice(&ip);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&4242u16.to_be_bytes());
        tcp[12] = 5 << 4;
        f.extend_from_slice(&tcp);
        f.extend_from_slice(payload);
        f
    }

    /// Deterministic bytes that are not a repeating pattern, so entropy over
    /// them is near the ceiling without depending on a real RNG.
    fn pseudo(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        (0..len)
            .map(|_| {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (s >> 33) as u8
            })
            .collect()
    }

    // ── pcap parsing ────────────────────────────────────────────────────────

    #[test]
    fn a_capture_shorter_than_its_header_is_named_not_guessed_at() {
        assert_eq!(read_pcap(&[]).unwrap_err(), PcapError::TooShort(0));
        assert_eq!(read_pcap(&[0u8; 10]).unwrap_err(), PcapError::TooShort(10));
        // An empty capture file is the exact shape of "the process started and
        // caught nothing", which must not read as a clean run.
        let empty = pcap_of(1, &[]);
        let p = read_pcap(&empty).expect("a header-only file parses");
        assert!(p.frames.is_empty());
        assert!(!p.truncated);
    }

    #[test]
    fn pcapng_is_reported_as_the_wrong_format_rather_than_as_corruption() {
        let mut ng = 0x0a0d_0d0au32.to_le_bytes().to_vec();
        ng.extend_from_slice(&[0u8; 40]);
        assert_eq!(read_pcap(&ng).unwrap_err(), PcapError::IsPcapng);
        assert!(read_pcap(&ng)
            .unwrap_err()
            .to_string()
            .contains("classic pcap"));
    }

    #[test]
    fn all_four_magics_parse_and_agree_on_the_timestamp() {
        let payload = b"payload".to_vec();
        let frame = udp4(&payload);
        // 1.5 s past the epoch, expressed in each of the four header forms.
        for (magic, big, nanos) in [
            (0xa1b2_c3d4u32, false, false),
            (0xa1b2_3c4du32, false, true),
            (0xd4c3_b2a1u32, true, false),
            (0x4d3c_b2a1u32, true, true),
        ] {
            let mut out = Vec::new();
            out.extend_from_slice(&magic.to_le_bytes());
            let w32 = |v: u32| -> [u8; 4] {
                if big {
                    v.to_be_bytes()
                } else {
                    v.to_le_bytes()
                }
            };
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&w32(1));
            out.extend_from_slice(&w32(1));
            out.extend_from_slice(&w32(if nanos { 500_000_000 } else { 500_000 }));
            out.extend_from_slice(&w32(frame.len() as u32));
            out.extend_from_slice(&w32(frame.len() as u32));
            out.extend_from_slice(&frame);

            let p = read_pcap(&out).expect("parses");
            assert_eq!(p.link_type, 1, "magic 0x{magic:08x}");
            assert_eq!(p.frames.len(), 1);
            assert_eq!(
                p.frames[0].unix_ns, 1_500_000_000,
                "magic 0x{magic:08x} must resolve to the same instant"
            );
        }
    }

    /// The capture process is killed rather than allowed to close its file, so
    /// a half-written trailing record is the normal ending, not corruption.
    #[test]
    fn a_capture_cut_mid_record_keeps_what_it_has_and_says_it_was_cut() {
        let full = pcap_of(
            1,
            &[(1_000_000_000, udp4(b"one")), (2_000_000_000, udp4(b"two"))],
        );
        let cut = &full[..full.len() - 5];
        let p = read_pcap(cut).expect("a cut capture still parses");
        assert_eq!(p.frames.len(), 1, "the complete record survives");
        assert!(p.truncated, "and the cut is reported");

        let whole = read_pcap(&full).expect("parses");
        assert_eq!(whole.frames.len(), 2);
        assert!(!whole.truncated);
    }

    #[test]
    fn an_absurd_record_length_stops_the_reader_instead_of_allocating() {
        let mut out = pcap_of(1, &[(1_000_000_000, udp4(b"one"))]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        let p = read_pcap(&out).expect("parses what it can");
        assert_eq!(p.frames.len(), 1);
        assert!(p.truncated);
    }

    // ── Frame decoding ──────────────────────────────────────────────────────

    #[test]
    fn ethernet_ipv4_udp_and_tcp_payloads_are_found() {
        let body = b"the payload we care about";
        let f = udp4(body);
        let r = transport_payload(1, &f).expect("udp decodes");
        assert_eq!(&f[r], body);

        let f = tcp4(body);
        let r = transport_payload(1, &f).expect("tcp decodes");
        assert_eq!(&f[r], body);
    }

    #[test]
    fn a_bare_tcp_acknowledgement_decodes_to_an_empty_payload() {
        let f = tcp4(b"");
        let r = transport_payload(1, &f).expect("decodes");
        assert!(r.is_empty(), "a pure ACK carries nothing");
    }

    /// Linux `any`, macOS loopback and a raw-IP capture all have to work: they
    /// are what an operator actually gets, and getting one of them wrong turns
    /// every payload into an "undecodable" and the run into a false negative.
    #[test]
    fn every_link_type_an_operator_is_likely_to_capture_on_decodes() {
        let body = b"needle-in-the-payload";

        // LINUX_SLL (libpcap < 1.10 with -i any).
        let mut sll = vec![0u8; 16];
        sll[14] = 0x08;
        sll[15] = 0x00;
        sll.extend_from_slice(&udp4(body)[14..]);
        let r = transport_payload(113, &sll).expect("SLL decodes");
        assert_eq!(&sll[r], body);

        // LINUX_SLL2 (libpcap >= 1.10 with -i any): protocol first.
        let mut sll2 = vec![0u8; 20];
        sll2[0] = 0x08;
        sll2[1] = 0x00;
        sll2.extend_from_slice(&udp4(body)[14..]);
        let r = transport_payload(276, &sll2).expect("SLL2 decodes");
        assert_eq!(&sll2[r], body);

        // BSD loopback, both byte orders for AF_INET.
        for af in [2u32.to_le_bytes(), 2u32.to_be_bytes()] {
            let mut null = af.to_vec();
            null.extend_from_slice(&udp4(body)[14..]);
            let r = transport_payload(0, &null).expect("NULL decodes");
            assert_eq!(&null[r], body);
        }

        // Raw IP, no link layer at all.
        let raw = udp4(body)[14..].to_vec();
        let r = transport_payload(101, &raw).expect("RAW decodes");
        assert_eq!(&raw[r], body);

        // A VLAN tag between the Ethernet header and the IP one.
        let mut vlan = vec![0u8; 14];
        vlan[12] = 0x81;
        vlan[13] = 0x00;
        vlan.extend_from_slice(&[0x00, 0x64, 0x08, 0x00]);
        vlan.extend_from_slice(&udp4(body)[14..]);
        let r = transport_payload(1, &vlan).expect("VLAN decodes");
        assert_eq!(&vlan[r], body);
    }

    #[test]
    fn ipv6_udp_decodes_including_one_extension_header() {
        let body = b"six";
        let mut f = vec![0u8; 14];
        f[12] = 0x86;
        f[13] = 0xDD;
        let mut ip6 = vec![0u8; 40];
        ip6[0] = 0x60;
        ip6[6] = 17;
        f.extend_from_slice(&ip6);
        let mut udp = vec![0u8; 8];
        udp[4..6].copy_from_slice(&((8 + body.len()) as u16).to_be_bytes());
        f.extend_from_slice(&udp);
        f.extend_from_slice(body);
        let r = transport_payload(1, &f).expect("plain IPv6 decodes");
        assert_eq!(&f[r], body);

        // With a hop-by-hop options header in front of the UDP one.
        let mut g = f[..14].to_vec();
        let mut ip6 = vec![0u8; 40];
        ip6[0] = 0x60;
        ip6[6] = 0; // hop-by-hop
        g.extend_from_slice(&ip6);
        let mut ext = vec![0u8; 8];
        ext[0] = 17;
        ext[1] = 0; // one 8-octet unit, header included
        g.extend_from_slice(&ext);
        g.extend_from_slice(&udp);
        g.extend_from_slice(body);
        let r = transport_payload(1, &g).expect("IPv6 + extension decodes");
        assert_eq!(&g[r], body);
    }

    #[test]
    fn undecodable_frames_are_classified_rather_than_dropped() {
        assert_eq!(
            transport_payload(999, &[0u8; 64]).unwrap_err(),
            Undecodable::UnsupportedLinkType
        );
        assert_eq!(
            transport_payload(1, &[0u8; 4]).unwrap_err(),
            Undecodable::ShortFrame
        );
        // ARP over Ethernet.
        let mut arp = vec![0u8; 14];
        arp[12] = 0x08;
        arp[13] = 0x06;
        arp.extend_from_slice(&[0u8; 28]);
        assert_eq!(transport_payload(1, &arp).unwrap_err(), Undecodable::NotIp);
        // ICMP over IPv4.
        let mut icmp = vec![0u8; 14];
        icmp[12] = 0x08;
        icmp[13] = 0x00;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 1;
        icmp.extend_from_slice(&ip);
        icmp.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            transport_payload(1, &icmp).unwrap_err(),
            Undecodable::UnsupportedIpProtocol
        );
        for u in [
            Undecodable::UnsupportedLinkType,
            Undecodable::ShortFrame,
            Undecodable::NotIp,
            Undecodable::UnsupportedIpVersion,
            Undecodable::UnsupportedIpProtocol,
        ] {
            assert!(!u.label().is_empty());
        }
    }

    /// Ethernet pads short frames to 60 bytes, and the UDP length field is the
    /// only thing that says where the payload really ends. Reading to the end
    /// of the frame instead would fold padding into every short payload and
    /// drag its entropy down.
    #[test]
    fn ethernet_padding_is_excluded_by_the_udp_length_field() {
        let body = b"tiny";
        let mut f = udp4(body);
        f.extend_from_slice(&[0u8; 20]);
        let r = transport_payload(1, &f).expect("decodes");
        assert_eq!(&f[r], body, "padding must not become payload");
    }

    // ── Entropy ─────────────────────────────────────────────────────────────

    #[test]
    fn shannon_entropy_matches_hand_computable_cases() {
        assert_eq!(shannon_bits_per_byte(&[]), 0.0);
        assert_eq!(
            shannon_bits_per_byte(&[7u8; 64]),
            0.0,
            "one symbol, no information"
        );
        // Two symbols, equally frequent: exactly one bit per byte.
        let two: Vec<u8> = (0..64)
            .map(|i| if i % 2 == 0 { 0u8 } else { 1u8 })
            .collect();
        assert!((shannon_bits_per_byte(&two) - 1.0).abs() < 1e-12);
        // All 256 values once each: exactly eight bits per byte.
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_bits_per_byte(&all) - 8.0).abs() < 1e-12);
    }

    /// The arithmetic bound is the whole reason entropy is reported twice. A
    /// short payload that is as uniform as it possibly can be still scores far
    /// below 8, and must not read as a finding.
    #[test]
    fn a_short_payload_is_bounded_by_arithmetic_not_by_cryptography() {
        let sixteen: Vec<u8> = (0..16u8).collect();
        let h = shannon_bits_per_byte(&sixteen);
        assert!((h - 4.0).abs() < 1e-12, "16 distinct bytes cap at log2(16)");
        assert!((entropy_ceiling(16) - 4.0).abs() < 1e-12);
        assert!(
            (h / entropy_ceiling(16) - 1.0).abs() < 1e-12,
            "as a fraction of its own ceiling it is at the maximum"
        );

        assert_eq!(entropy_ceiling(0), 0.0);
        assert_eq!(entropy_ceiling(1), 0.0);
        assert!((entropy_ceiling(256) - 8.0).abs() < 1e-12);
        assert!(
            (entropy_ceiling(4096) - 8.0).abs() < 1e-12,
            "the ceiling stops at 8 whatever the length"
        );
    }

    #[test]
    fn the_entropy_block_separates_full_scale_payloads_from_short_ones() {
        let mut samples = Vec::new();
        let mut lengths = Vec::new();
        for i in 0..10 {
            let p = pseudo(1200, i);
            samples.push((p.len(), shannon_bits_per_byte(&p)));
            lengths.push(p.len());
        }
        for i in 0..5 {
            let p = pseudo(40, 100 + i);
            samples.push((p.len(), shannon_bits_per_byte(&p)));
            lengths.push(p.len());
        }
        samples.push((1, 0.0));
        lengths.push(1);

        let b = entropy_block(&samples, &lengths);
        assert_eq!(b.payloads, 16);
        assert_eq!(
            b.full_scale_payloads, 10,
            "only the 1200 B ones can reach 8"
        );
        assert_eq!(b.trivial_payloads, 1);
        assert_eq!(b.bits_per_byte.count, 10, "the sample size travels with it");
        assert_eq!(b.ratio_of_ceiling.count, 15, "one-byte payload excluded");
        assert_eq!(b.payload_bytes.count, 16, "lengths cover everything");
        assert!(
            b.bits_per_byte.min > 7.5,
            "unstructured payloads sit near the ceiling, got {}",
            b.bits_per_byte.min
        );
        assert!(b.ratio_of_ceiling.min > 0.9, "{:?}", b.ratio_of_ceiling);

        // With nothing to summarise the distribution is absent, not zero.
        let empty = entropy_block(&[], &[]);
        assert_eq!(empty.bits_per_byte.count, 0);
        assert_eq!(empty.payloads, 0);
    }

    // ── Searching ───────────────────────────────────────────────────────────

    #[test]
    fn substring_search_finds_boundaries_and_rejects_near_misses() {
        assert_eq!(contains(b"abcdef", b"abc"), Some(0));
        assert_eq!(contains(b"abcdef", b"def"), Some(3));
        assert_eq!(contains(b"abcdef", b"cd"), Some(2));
        assert_eq!(contains(b"abcdef", b"abcdef"), Some(0));
        assert_eq!(contains(b"abcdef", b"abcdefg"), None);
        assert_eq!(contains(b"abcdef", b"acf"), None);
        assert_eq!(contains(b"aaab", b"aab"), Some(1), "overlapping prefixes");
        assert_eq!(contains(b"", b"a"), None);
        assert_eq!(
            contains(b"abc", b""),
            None,
            "an empty needle matches nothing"
        );
    }

    // ── The verdict ─────────────────────────────────────────────────────────

    fn control() -> Needle {
        Needle::new(
            "protocol_variant",
            b"phantom-default-1".to_vec(),
            Polarity::MustAppear,
        )
    }

    fn app_payload(body: &[u8]) -> Needle {
        Needle::new("echo-0", body.to_vec(), Polarity::MustNotAppear)
    }

    /// A clean run: the control is in the handshake, the application bytes are
    /// nowhere, and there is post-handshake traffic to have searched.
    #[test]
    fn a_clean_capture_passes_and_says_where_the_control_was_found() {
        let secret = b"MARKER-0000-application-bytes";
        let mut hs = b"\x03\x11\x00\x00\x00phantom-default-1".to_vec();
        hs.extend_from_slice(&pseudo(900, 1));
        let cap = pcap_of(
            1,
            &[
                (1_000_000_000, udp4(&hs)),
                (1_100_000_000, udp4(&pseudo(1100, 2))),
                (3_000_000_000, udp4(&pseudo(1100, 3))),
                (3_100_000_000, udp4(&pseudo(1100, 4))),
            ],
        );
        let f =
            analyze(&cap, &[control(), app_payload(secret)], 2_000_000_000).expect("analysis runs");

        assert_eq!(f.verdict, Verdict::Pass, "{:?}", f.reasons);
        assert!(f.reasons.is_empty());
        assert_eq!(f.handshake_frames, 2);
        assert_eq!(f.established_frames, 2);
        assert_eq!(f.frames_decoded, 4);
        assert!(f.undecodable.is_empty());

        let ctl = &f.needles[0];
        assert_eq!(ctl.frames_hit, 1);
        assert_eq!(ctl.hits_in_handshake, 1);
        assert_eq!(ctl.hits_in_established, 0);
        assert_eq!(ctl.first_frame, Some(0));
        assert_eq!(f.needles[1].frames_hit, 0);

        assert_eq!(f.established_entropy.payloads, 2);
        assert_eq!(f.established_entropy.full_scale_payloads, 2);
        assert_eq!(f.handshake_entropy.payloads, 2);
    }

    /// The rule the whole design turns on. A search that finds no application
    /// bytes *and* fails its own control has demonstrated nothing, and must
    /// report a failure in those words rather than a pass.
    #[test]
    fn a_missing_positive_control_fails_the_run_even_with_a_clean_negative_search() {
        let cap = pcap_of(
            1,
            &[
                (1_000_000_000, udp4(&pseudo(900, 7))),
                (3_000_000_000, udp4(&pseudo(1100, 8))),
            ],
        );
        let f = analyze(&cap, &[control(), app_payload(b"MARKER-0")], 2_000_000_000)
            .expect("analysis runs");

        assert_eq!(f.verdict, Verdict::Failed);
        assert_eq!(
            f.needles[0].frames_hit, 0,
            "the control is genuinely absent"
        );
        assert_eq!(f.needles[1].frames_hit, 0, "and so are the app bytes");
        let joined = f.reasons.join(" ");
        assert!(joined.contains("positive control"), "{joined}");
        assert!(
            joined.contains("failed run, not a passing one"),
            "the verdict must be stated in those terms: {joined}"
        );
    }

    #[test]
    fn an_application_payload_on_the_wire_fails_and_names_the_frame() {
        let secret = b"MARKER-0000-application-bytes";
        let mut leaked = pseudo(600, 9);
        leaked.extend_from_slice(secret);
        let mut hs = b"phantom-default-1".to_vec();
        hs.extend_from_slice(&pseudo(900, 10));
        let cap = pcap_of(
            1,
            &[(1_000_000_000, udp4(&hs)), (3_000_000_000, udp4(&leaked))],
        );
        let f =
            analyze(&cap, &[control(), app_payload(secret)], 2_000_000_000).expect("analysis runs");

        assert_eq!(f.verdict, Verdict::Failed);
        assert_eq!(f.needles[1].frames_hit, 1);
        assert_eq!(f.needles[1].hits_in_established, 1);
        assert_eq!(f.needles[1].first_frame, Some(1));
        let joined = f.reasons.join(" ");
        assert!(joined.contains("plaintext on the wire"), "{joined}");
        assert!(joined.contains("echo-0"), "{joined}");
    }

    /// A capture that caught only the handshake cannot say anything about
    /// application data, however clean it looks.
    #[test]
    fn a_capture_with_no_established_traffic_is_not_a_pass() {
        let mut hs = b"phantom-default-1".to_vec();
        hs.extend_from_slice(&pseudo(900, 11));
        let cap = pcap_of(1, &[(1_000_000_000, udp4(&hs))]);
        let f = analyze(&cap, &[control(), app_payload(b"MARKER")], 2_000_000_000)
            .expect("analysis runs");
        assert_eq!(f.verdict, Verdict::Failed);
        assert!(
            f.reasons.iter().any(|r| r.contains("vacuous")),
            "{:?}",
            f.reasons
        );
    }

    #[test]
    fn an_empty_capture_is_not_a_pass_either() {
        let cap = pcap_of(1, &[]);
        let f = analyze(&cap, &[control()], 1).expect("analysis runs");
        assert_eq!(f.verdict, Verdict::Failed);
        assert!(f.reasons.iter().any(|r| r.contains("no frames at all")));
    }

    /// An observed needle records what it found and changes no verdict — it is
    /// there for material that is open by design, where neither presence nor
    /// absence is a defect.
    #[test]
    fn an_observed_needle_is_recorded_without_affecting_the_verdict() {
        let mut hs = b"phantom-default-1".to_vec();
        hs.extend_from_slice(b"www.example.com");
        hs.extend_from_slice(&pseudo(900, 12));
        let cap = pcap_of(
            1,
            &[
                (1_000_000_000, udp4(&hs)),
                (3_000_000_000, udp4(&pseudo(1100, 13))),
            ],
        );
        let sni = Needle::new("sni", b"www.example.com".to_vec(), Polarity::Observed);
        let f = analyze(&cap, &[control(), sni], 2_000_000_000).expect("analysis runs");
        assert_eq!(f.verdict, Verdict::Pass, "{:?}", f.reasons);
        assert_eq!(f.needles[1].frames_hit, 1);

        // And its absence is equally not a verdict.
        let absent = Needle::new("sni", b"not-present-here".to_vec(), Polarity::Observed);
        let g = analyze(&cap, &[control(), absent], 2_000_000_000).expect("analysis runs");
        assert_eq!(g.verdict, Verdict::Pass, "{:?}", g.reasons);
        assert_eq!(g.needles[1].frames_hit, 0);
    }

    /// The negative search runs over whole frames, so a leak survives even if
    /// the transport decoder cannot reach the payload at all. Without that,
    /// a decoding gap would silently become a clean result.
    #[test]
    fn a_leak_is_caught_even_in_a_frame_the_decoder_cannot_parse() {
        let secret = b"MARKER-0000-application-bytes";
        let mut junk = vec![0xFFu8; 8];
        junk.extend_from_slice(secret);
        let mut hs = b"phantom-default-1".to_vec();
        hs.extend_from_slice(&pseudo(900, 14));
        let cap = pcap_of(
            1,
            &[
                (1_000_000_000, udp4(&hs)),
                (3_000_000_000, udp4(&pseudo(1100, 15))),
                (3_100_000_000, junk),
            ],
        );
        let f =
            analyze(&cap, &[control(), app_payload(secret)], 2_000_000_000).expect("analysis runs");
        assert_eq!(f.verdict, Verdict::Failed);
        assert_eq!(f.needles[1].frames_hit, 1);
        assert_eq!(f.frames_decoded, 2, "the junk frame did not decode");
        assert_eq!(
            f.undecodable.iter().map(|u| u.frames).sum::<usize>(),
            1,
            "and it is reported rather than dropped"
        );
    }

    /// Every reason a run failed has to survive to the artifact, and the record
    /// has to round-trip through JSON, because that is where it is read.
    #[test]
    fn findings_round_trip_through_json_with_their_reasons_intact() {
        let f = Findings::skipped("no capture: tcpdump is not installed on this host");
        assert_eq!(f.verdict, Verdict::Skipped);
        let s = serde_json::to_string(&f).expect("encode");
        let back: Findings = serde_json::from_str(&s).expect("decode");
        assert_eq!(back, f);
        let v: serde_json::Value = serde_json::from_str(&s).expect("decode");
        assert_eq!(v["verdict"], "skipped");
        assert!(v["reasons"][0]
            .as_str()
            .unwrap_or_default()
            .contains("tcpdump"));
        assert_eq!(Verdict::Pass.as_str(), "pass");
        assert_eq!(Verdict::Failed.as_str(), "failed");
    }

    /// A skip carries the statement too: the part of the check that does not
    /// depend on a capture is still true when no capture was taken.
    #[test]
    fn a_skip_still_carries_the_encrypted_flag_statement() {
        let f = Findings::skipped("no privileges");
        assert_eq!(f.encrypted_flag, encrypted_flag_statement());
        assert!(!f.encrypted_flag.is_empty());
    }

    // ── What the capture cannot answer ──────────────────────────────────────

    /// The statement is the only place the difference between "measured" and
    /// "read out of the source" is written down, so its substance is pinned
    /// here rather than left to prose drift.
    #[test]
    fn the_encrypted_flag_statement_says_what_it_must() {
        let all = encrypted_flag_statement().join("\n");
        assert!(
            all.contains("Answered from the source, not from the capture"),
            "the first thing it must say is which of the two it is"
        );
        assert!(
            all.contains("header protection masks the header"),
            "and why the capture cannot reach it"
        );
        assert!(
            all.contains("v2_recv_drops_unencrypted_non_empty_post_handshake_payload")
                && all.contains("forged_unencrypted_fin_does_not_close_a_stream"),
            "the tests that do pin it must be named"
        );
        assert!(
            all.contains("core/tests/security_invariants.rs") && all.contains("contains no test"),
            "and the gap must be stated, not papered over"
        );
        assert!(
            all.contains("record_unencrypted_dropped") && all.contains("no-op"),
            "including that there is no counter to fall back on"
        );
        // Every line has to stand on its own in a summary; none may be a stub.
        for line in ENCRYPTED_FLAG_STATEMENT {
            assert!(line.len() > 80, "not a statement: {line}");
        }
    }

    // ── The probe's own payloads ────────────────────────────────────────────

    /// The framing figure the const assertions above rest on has to match what
    /// the testbed actually puts around a payload. If a field were added to the
    /// reply the build-time check would still pass while the message quietly
    /// outgrew its chunk, so the arithmetic is tied to a real encoding here.
    #[test]
    fn the_framing_allowance_matches_a_real_reply_on_the_wire() {
        let msg = crate::proto::Msg::EchoReply {
            seq: 1,
            client_send_ns: 2,
            server_recv_ns: 3,
            server_send_ns: 4,
            payload: vec![0u8; PROBE_PAYLOAD_BYTES],
        };
        let wire = crate::framing::encode_framed(&msg);
        assert_eq!(
            wire.len(),
            PROBE_PAYLOAD_BYTES + PROBE_FRAMING_BYTES,
            "the framing allowance is {PROBE_FRAMING_BYTES} B; the encoding says otherwise"
        );
        assert!(wire.len() <= phantom_protocol::transport::mtu::MAX_APP_CHUNK);
    }

    #[test]
    fn markers_are_distinct_printable_and_carry_the_run_nonce() {
        let a = probe_marker(0x0123_4567_89AB_CDEF, 0);
        let b = probe_marker(0x0123_4567_89AB_CDEF, 1);
        assert_ne!(a, b, "each message must be identifiable from a hit");
        assert_ne!(a, probe_marker(1, 0), "two runs must not share needles");
        assert!(a.contains("0123456789abcdef"), "{a}");
        assert!(a.is_ascii() && a.chars().all(|c| !c.is_control()), "{a}");
        assert!(
            a.len() >= 32,
            "a short marker would collide with unrelated bytes by chance: {a}"
        );
    }

    #[test]
    fn the_needle_set_leads_with_the_control_and_covers_every_message_twice() {
        let messages: Vec<(String, Vec<u8>)> = (0..3)
            .map(|i| {
                let m = probe_marker(7, i);
                let mut p = m.as_bytes().to_vec();
                p.extend_from_slice(&pseudo(PROBE_PAYLOAD_BYTES - m.len(), i as u64));
                (m, p)
            })
            .collect();
        let n = needles_for(&messages, b"phantom-default-1");

        assert_eq!(n.len(), 1 + 3 * 2);
        assert_eq!(n[0].polarity, Polarity::MustAppear);
        assert_eq!(n[0].label, "protocol_variant");
        assert!(
            n[1..].iter().all(|x| x.polarity == Polarity::MustNotAppear),
            "everything the probe generated must be absent"
        );
        // Whole payload and leading marker, both present, both distinct.
        assert!(n[1].bytes.len() == PROBE_PAYLOAD_BYTES);
        assert!(n[2].bytes.len() < n[1].bytes.len());
        assert!(n[1].bytes.starts_with(&n[2].bytes), "the marker leads it");
        let labels: std::collections::HashSet<&str> = n.iter().map(|x| x.label.as_str()).collect();
        assert_eq!(labels.len(), n.len(), "labels must identify a hit uniquely");

        // And the whole set works end to end against a capture that leaked one
        // of them: the run fails and the label says which message it was.
        let mut hs = b"phantom-default-1".to_vec();
        hs.extend_from_slice(&pseudo(600, 99));
        let cap = pcap_of(
            1,
            &[
                (1_000_000_000, udp4(&hs)),
                (3_000_000_000, udp4(&messages[1].1)),
            ],
        );
        let f = analyze(&cap, &n, 2_000_000_000).expect("analysis runs");
        assert_eq!(f.verdict, Verdict::Failed);
        assert!(
            f.reasons.iter().any(|r| r.contains(&messages[1].0)),
            "{:?}",
            f.reasons
        );
    }

    // ── The capture driver ──────────────────────────────────────────────────

    #[test]
    fn the_filter_is_anchored_on_the_peer_and_covers_both_transports() {
        let f = filter_for("198.51.100.7", 4243);
        assert_eq!(
            f, "host 198.51.100.7 and (tcp port 4243 or udp port 4243)",
            "the filter must be reproducible by hand"
        );
        // IPv6 literals go through unchanged: tcpdump takes them as-is.
        assert!(filter_for("2001:db8::1", 4242).contains("host 2001:db8::1"));
    }

    #[test]
    fn the_capture_command_takes_whole_frames_and_flushes_every_one() {
        let req = CaptureRequest {
            interface: "any".into(),
            filter: filter_for("198.51.100.7", 4243),
            path: PathBuf::from("/tmp/x.pcap"),
        };
        let args = tcpdump_args(&req);
        assert!(args.contains(&"-U".to_string()), "{args:?}");
        assert_eq!(
            args.windows(2).find(|w| w[0] == "-s").map(|w| &w[1]),
            Some(&"0".to_string()),
            "a snaplen cut would truncate exactly the payload being searched"
        );
        assert!(
            args.contains(&"-n".to_string()),
            "no name resolution mid-run"
        );
        assert_eq!(
            args.windows(2).find(|w| w[0] == "-w").map(|w| &w[1]),
            Some(&"/tmp/x.pcap".to_string())
        );
        assert_eq!(
            args.last(),
            Some(&req.filter),
            "the filter is positional and must come last"
        );
        assert_eq!(
            args.windows(2).find(|w| w[0] == "-i").map(|w| &w[1]),
            Some(&"any".to_string())
        );
    }

    /// The most common failure by far, and the one whose message has to tell an
    /// operator what to do next.
    #[test]
    fn a_permission_refusal_is_diagnosed_with_the_remedy_for_each_platform() {
        let msg = diagnose("tcpdump: en0: You don't have permission to capture on that device");
        assert!(msg.contains("elevated rights"), "{msg}");
        assert!(msg.contains("setcap cap_net_raw"), "{msg}");
        assert!(msg.contains("sudo"), "{msg}");
        assert!(
            msg.contains("permission to capture"),
            "tcpdump's own words survive: {msg}"
        );
        assert!(
            !msg.contains("tcpdump: tcpdump:"),
            "quoted once, not twice: {msg}"
        );

        assert!(diagnose("tcpdump: /dev/bpf0: Permission denied").contains("elevated rights"));
        // A refusal that does not name itself is still attributed.
        let bare = diagnose("(no devices found) /dev/bpf: Operation not permitted");
        assert!(bare.contains("elevated rights"), "{bare}");
        assert!(bare.contains("tcpdump: (no devices found)"), "{bare}");
    }

    #[test]
    fn other_refusals_are_passed_through_rather_than_flattened() {
        let msg = diagnose("tcpdump: any: No such device exists");
        assert!(msg.contains("No such device exists"), "{msg}");
        assert!(!msg.contains("elevated rights"), "{msg}");
        assert!(
            diagnose("   ").contains("said nothing"),
            "silence is itself a reason"
        );
        // Multi-line output reports its first substantive line, not a wall.
        let multi = diagnose("\n\ntcpdump: syntax error in filter expression\nusage: tcpdump ...");
        assert!(multi.contains("syntax error"), "{multi}");
        assert!(!multi.contains("usage:"), "{multi}");
    }

    /// The reader must survive a file the operator can produce by accident —
    /// an empty one, a text one, someone else's format — without the run
    /// mistaking any of them for a clean result.
    #[test]
    fn a_capture_that_is_not_a_capture_is_a_skip_reason_not_a_pass() {
        for junk in [b"".to_vec(), b"not a pcap at all".to_vec(), vec![0u8; 24]] {
            let e = read_pcap(&junk).expect_err("must not parse");
            assert!(!e.to_string().is_empty());
            let f = Findings::skipped(e.to_string());
            assert_eq!(f.verdict, Verdict::Skipped);
        }
    }

    #[test]
    fn read_capped_stops_at_its_bound() {
        let dir = std::env::temp_dir().join(format!("tb-wc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("c.pcap");
        std::fs::write(&path, vec![0xABu8; 4096]).expect("write");
        assert_eq!(read_capped(&path, 100).expect("read").len(), 100);
        assert_eq!(read_capped(&path, 8192).expect("read").len(), 4096);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
