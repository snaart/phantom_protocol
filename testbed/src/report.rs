//! Record schemas and JSONL output.
//!
//! Two write paths, deliberately different:
//!
//! - **Client samples** accumulate in memory ([`SampleSink`]) and are written
//!   once the scenario ends. A latency measurement must never straddle a
//!   `write(2)`: buffered or not, a flush inside the hot loop would show up in
//!   the very percentiles the run exists to measure.
//! - **Server records** go through an mpsc channel to a single collector task
//!   ([`JsonlWriter`]), keeping all file I/O off the session handlers.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::stats::{Summary, Throughput};

/// Wall-clock nanoseconds since the Unix epoch.
///
/// Used for cross-host correlation (and, with the `clock_sync` offset, for
/// one-way delay estimates). Never used to measure a duration on one host —
/// that is [`std::time::Instant`]'s job, because the wall clock can step.
pub fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

pub fn unix_secs_f64() -> f64 {
    unix_nanos() as f64 / 1e9
}

/// RFC3339-ish UTC timestamp without pulling in a date library.
pub fn utc_stamp() -> String {
    let total = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (total / 86_400, total % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Compact run-id: `YYYYmmdd-HHMMSS`.
pub fn run_id_stamp() -> String {
    utc_stamp()
        .replace(['-', ':'], "")
        .replace('T', "-")
        .replace('Z', "")
}

/// Howard Hinnant's `civil_from_days` — days since the Unix epoch to (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ── Legs ────────────────────────────────────────────────────────────────────

/// The transports this harness drives over a real network.
///
/// WebSocket, WASI and Embedded are out of scope by construction — they need a
/// browser, a wasmtime host, or a serial line respectively, none of which this
/// two-host setup has.
// `snake_case` on all three surfaces is load-bearing, not cosmetic: the JSON
// `leg` field, the CLI value, and `as_str()` (which names the samples
// directory) must be the same token. Under `lowercase` they diverge —
// `RawTcp` serialises as "rawtcp" while the directory is "raw_tcp" — and an
// analysis joining samples to summaries on that field would silently fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
pub enum Leg {
    /// PhantomUDP — the production transport; the only migration-capable leg.
    Udp,
    /// Phantom over TCP.
    Tcp,
    /// mimic-TLS over TCP (obfuscation only).
    Mimic,
    /// QUIC via `quinn`. **Reference leg** — not the protocol under test.
    ///
    /// A mature implementation of the same class (reliable, encrypted,
    /// multiplexed, over UDP), driven over the same path in the same run so
    /// that "how does this compare" is a measurement rather than an opinion.
    /// Its cryptography is classical TLS 1.3, so its handshake latency is not
    /// comparable like-for-like with a hybrid post-quantum one; its throughput
    /// and loss behaviour are.
    Quic,
    /// Raw TCP echo, no Phantom. Control group.
    RawTcp,
    /// Raw UDP echo, no Phantom. Control group.
    RawUdp,
}

impl Leg {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Mimic => "mimic",
            Self::Quic => "quic",
            Self::RawTcp => "raw_tcp",
            Self::RawUdp => "raw_udp",
        }
    }

    /// True for the legs that run a real Phantom session — the protocol under
    /// test. False for both the raw-socket controls and the QUIC reference.
    pub fn is_phantom(self) -> bool {
        matches!(self, Self::Udp | Self::Tcp | Self::Mimic)
    }

    /// True for a leg that carries a full transport protocol other than the one
    /// under test, so its numbers are a yardstick rather than a result.
    pub fn is_reference(self) -> bool {
        matches!(self, Self::Quic)
    }

    /// Only PhantomUDP supports `migrate()`; every other leg answers
    /// `CoreError::Unsupported`.
    pub fn supports_migration(self) -> bool {
        matches!(self, Self::Udp)
    }
}

impl std::fmt::Display for Leg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Build identity ──────────────────────────────────────────────────────────

/// Which code produced a binary.
///
/// Resolved at compile time by `build.rs`, not at run time. Asking git when the
/// process starts answers a question about the *current directory* — normally a
/// results folder on the operator's laptop, or a VPS with no checkout at all —
/// rather than about the binary, so two runs of visibly different code could
/// carry the same stamp or none. Baking it in is what lets an analysis comparing
/// two runs prove they were not the same build.
///
/// `git_sha` reads `unknown` when the source was built outside a repository (a
/// tarball, a vendored copy). That is a normal case and says so, which is better
/// than a plausible-looking wrong answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildId {
    pub git_sha: String,
    /// True when tracked files differed from the commit at build time. A dirty
    /// build is not reproducible from its SHA, and a comparison that treats it
    /// as though it were is drawing a conclusion about code nobody has.
    pub git_dirty: bool,
    pub version: String,
}

impl BuildId {
    pub fn current() -> Self {
        Self {
            git_sha: env!("TESTBED_GIT_SHA").to_string(),
            git_dirty: env!("TESTBED_GIT_DIRTY") == "true",
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Compact `<sha>` or `<sha>-dirty`, for a log line or an event detail.
    pub fn label(&self) -> String {
        if self.git_dirty {
            format!("{}-dirty", self.git_sha)
        } else {
            self.git_sha.clone()
        }
    }
}

// ── Run metadata ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeta {
    pub run_id: String,
    pub profile: String,
    pub started_utc: String,
    pub started_unix_ns: u64,
    pub finished_utc: Option<String>,
    pub finished_unix_ns: Option<u64>,

    pub server_host: String,
    pub server_resolved_addr: Option<String>,
    pub pin_hex: String,
    pub legs: Vec<Leg>,

    pub client: HostInfo,
    pub testbed_version: String,
    pub phantom_version: String,
    /// The probe's own build.
    pub build: BuildId,
    /// The daemon's build, read from its `STATS` reply during `clock_sync`.
    ///
    /// `None` when no Phantom leg was reachable to ask over. Recorded here
    /// rather than only on the server so one artifact answers "which two builds
    /// produced this comparison" without needing the daemon's directory too.
    pub daemon_build: Option<BuildId>,

    pub clock: Option<ClockEstimate>,

    /// Intervals during which the probe's own host was not executing.
    ///
    /// Empty on a run that stayed awake, and `#[serde(default)]` so artifacts
    /// written before this field existed still load — they are runs for which
    /// the question was not asked, which is a different thing from a run that
    /// answered no, and only the absence of the field distinguishes them.
    ///
    /// A suspension makes every scenario whose window overlaps it unreadable
    /// as a measurement of the path: the connect inside it records `Timeout`
    /// while the daemon, still running, completes the handshake and counts it
    /// a success. See [`crate::suspend`].
    #[serde(default)]
    pub suspensions: Vec<crate::suspend::Suspension>,

    /// Everything a reader must know before over-reading this data set.
    ///
    /// Written into the artifact itself rather than left to a README, because
    /// the caveats travel with the numbers or they are not caveats at all.
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub cpu_count: usize,
    pub local_addrs: Vec<String>,
}

/// Result of the four-timestamp clock exchange.
///
/// `offset_ns` is the estimated client→server clock offset. `dispersion_ns` is
/// the spread across probes: a large dispersion means the offset estimate is
/// weak and one-way delays computed from it should not be trusted. Recording
/// the dispersion alongside the offset is what makes the derived numbers
/// falsifiable instead of merely precise-looking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockEstimate {
    pub samples: usize,
    pub offset_ns: i64,
    pub dispersion_ns: u64,
    pub min_rtt_ns: u64,
    pub method: String,
}

// ── Client sample records ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeSample {
    pub seq: u64,
    pub leg: Leg,
    pub t_unix_ns: u64,
    /// Time for the synchronous part of `connect_*`: DNS, TCP connect (or UDP
    /// socket setup), and session construction. The handshake has **not** run
    /// yet at this point — `connect_pinned*` returns a session in `Connecting`
    /// state and drives the handshake on a background task.
    pub setup_ns: Option<u64>,
    /// Time from the `connect_*` call to a session that has completed the
    /// hybrid post-quantum handshake and verified the pinned server identity.
    /// This is the number worth calling "handshake latency".
    pub connect_ns: Option<u64>,
    /// Time for the first application round trip after the handshake.
    pub first_rtt_ns: Option<u64>,
    pub ok: bool,
    pub error: Option<String>,
    pub error_kind: Option<String>,
}

/// One deliberately damaged handshake: a connect whose server reply flight was
/// dropped before it reached the client, and what the listener did about it.
///
/// Every field here exists to stop the record being read as a pass when it is
/// not one. A connect that completed while nothing was swallowed says nothing;
/// a connect that completed while the listener recorded no repeat says the
/// repair was not what carried it; and an elapsed time with no baseline beside
/// it cannot say whether the listener's repeat or the client's own third
/// retransmission got the session open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRepairSample {
    pub seq: u64,
    pub leg: Leg,
    pub t_unix_ns: u64,
    /// Datagrams the relay refused to deliver to the client. Zero means the
    /// attempt crossed a clean path and is evidence about nothing.
    pub swallowed_datagrams: u64,
    /// How many datagrams the doomed flight declared itself to be, from its own
    /// `total_chunks`. Differs from the count above only when the path lost part
    /// of the flight before the relay saw it, which leaves swallow budget to
    /// spend on the repeat and costs the connect one more retransmit.
    pub flight_total_chunks: Option<u16>,
    /// Wall clock from the first socket call to a session that has completed the
    /// handshake and verified the pinned identity.
    pub ready_ns: Option<u64>,
    /// The same measurement through the same relay with nothing swallowed.
    ///
    /// The denominator. An elapsed connect on its own is a number; against this
    /// it is the cost of the loss, with the relay's own hop cancelled out of
    /// both sides.
    pub baseline_ready_ns: Option<u64>,
    /// The client's first handshake-retransmit interval and the whole budget it
    /// sits in, carried so the elapsed times above can be read against the
    /// schedule that produced them without the reader holding a copy of it.
    pub first_retransmit_ns: u64,
    pub retransmit_budget_ns: u64,
    /// Movement in `initial_flights_on_committed_route_total` on the **server**
    /// across this attempt: the client's repeated flight arriving, one per
    /// question. The per-datagram counter of the same event is deliberately not
    /// what this reads — it would count three per question and make the pair
    /// below unreadable.
    pub asked_delta: Option<u64>,
    /// Movement in `handshake_flight_repeated_total`: an answer going back, also
    /// one per flight.
    ///
    /// Asked-and-answered is a repaired connect. Asked-and-not-answered is a
    /// connect the listener's retention could not cover. The pair is the whole
    /// reading, and either number alone is ambiguous between them — which is why
    /// both sides of it have to be counted in the same unit.
    pub answered_delta: Option<u64>,
    /// Movement in `handshake_flight_evicted_total` and
    /// `handshake_flight_refused_total` — the two ways retention fails to cover
    /// a session, by running out of budget and by never arming.
    pub evicted_delta: Option<u64>,
    pub refused_delta: Option<u64>,
    /// The listener's counters after the attempt, in full. Deltas are the
    /// reading, but a delta cannot be re-derived from another delta, and these
    /// are what a later question about this run gets to ask.
    pub server_counters: Option<ClientMetrics>,
    /// True only for an attempt that both lost a flight and was repaired.
    pub ok: bool,
    /// `repaired`, or `inconclusive: …`, or `failed: …` — in the artifact's own
    /// words, so a reader does not have to reconstruct the rule from the fields.
    pub verdict: String,
    pub error: Option<String>,
    pub error_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RttSample {
    pub seq: u64,
    pub leg: Leg,
    pub payload_bytes: usize,
    pub t_unix_ns: u64,
    pub rtt_ns: u64,
    /// Server-side receive stamp, raw. Comparable to `t_unix_ns` only after
    /// applying the run's clock offset.
    pub server_recv_unix_ns: Option<u64>,
    pub server_send_unix_ns: Option<u64>,
    /// Server's internal turnaround (`server_send - server_recv`) — this one is
    /// single-clock and therefore exact, no offset needed.
    pub server_turnaround_ns: Option<u64>,
}

/// One probe of the session's message-boundary behaviour.
///
/// `PhantomSession::send()` splits payloads above its internal 1156-byte chunk
/// size, and the peer's `recv()` yields each piece separately. This
/// record measures where that starts and how far it goes, per leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageIntegritySample {
    pub leg: Leg,
    pub t_unix_ns: u64,
    /// Application payload offered to `send()`.
    pub payload_bytes: usize,
    /// Bytes actually on the wire for this message (payload + testbed header).
    pub message_bytes: usize,
    /// Number of `recv()` results the reply arrived in. `1` means the boundary
    /// was preserved.
    pub recv_chunks: usize,
    pub chunk_sizes: Vec<usize>,
    /// Whether the echoed payload came back byte-identical after reassembly.
    pub payload_intact: bool,
    pub rtt_ns: Option<u64>,
    pub error: Option<String>,
}

/// One observation of the sender's congestion-control state during a transfer.
///
/// Throughput alone cannot tell a window pinned at its floor from a slow link,
/// and the two call for opposite responses. This series is what separates them:
/// if `cwnd_bytes` never rises while `inflight_bytes` sits against it, the
/// sender is the bottleneck, whatever the link can do.
///
/// **On the `quic` reference leg most of these fields are zero.** quinn exposes
/// `cwnd` and a smoothed RTT and nothing else of this shape, so only
/// `cwnd_bytes` and `min_rtt_us` carry values there — and `min_rtt_us` holds
/// quinn's *smoothed* RTT, which is a different statistic from Phantom's
/// windowed minimum. `inflight_bytes`, `bottleneck_bw_bps`,
/// `last_delivery_rate_bps`, `bw_filter_window_ms`, `pacing_rate_bps`,
/// `delivered_bytes` and `app_limited` stay zero/false rather than being filled
/// with an approximation, and `state` reads `quic:cubic` — quinn's default
/// controller is loss-based, so it has no BBR phase to report and its window
/// shape is not comparable with a BBR one. Compare the two on outcomes
/// (throughput, loss, recovery), not on the shape of the curve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSample {
    pub leg: Leg,
    pub phase: String,
    pub t_unix_ns: u64,
    pub elapsed_ms: u64,
    /// Congestion window, bytes. The floor is 5600 (4 × 1400).
    pub cwnd_bytes: u64,
    pub inflight_bytes: u64,
    /// Estimated bottleneck bandwidth, bytes/sec.
    pub bottleneck_bw_bps: u64,
    /// The single most recent delivery-rate sample, bytes/sec — the figure the
    /// estimator computed for the last acknowledgement, before its maximum
    /// filter decided whether to retain it.
    ///
    /// Recorded because the field above cannot answer the question a run
    /// actually asks of it. `bottleneck_bw_bps` is a maximum over the
    /// estimator's horizon — the one `bw_filter_window_ms` below names — and it
    /// gets compared against bytes delivered over a 500 ms
    /// sample interval; a maximum over the longer window exceeds a mean over
    /// the shorter one by construction, so a ratio modestly above one is partly
    /// an artefact of comparing two different statistics rather than evidence of
    /// anything. With the raw sample in the same row the two come apart: a raw
    /// sample tracking the delivered rate while the estimate sits far above it
    /// is a retained peak, and a raw sample that itself reads high is the sample
    /// arithmetic.
    ///
    /// **It is a point sample and only its central value across a sweep means
    /// anything.** The sampler takes whichever acknowledgement happened to be
    /// the last one before its instant, so the spread of this column over a run
    /// describes the sampler's cadence rather than the connection — reading a
    /// p90 or a peak off it would put the instrument back inside the very
    /// mismatch between statistics it was added to separate. `analyze.py` prints
    /// a median here and percentiles only for `bottleneck_bw_bps`, and names the
    /// statistic behind each line so the two cannot be read as the same kind of
    /// number.
    ///
    /// Defaulted on deserialize so runs recorded before it existed still load;
    /// it reads zero on the `quic` leg and on any run older than this field.
    #[serde(default)]
    pub last_delivery_rate_bps: u64,
    /// The horizon `bottleneck_bw_bps` is a maximum over, in milliseconds, read
    /// from the library this binary was built against.
    ///
    /// It rides in the row because the row is what someone reads a year later,
    /// and the two numbers beside each other are only interpretable if the
    /// window behind the first one is known. Carrying it here is the difference
    /// between an analysis script *deriving* that window and *remembering* it: a
    /// remembered copy goes stale the day the constant moves, and the failure is
    /// a label confidently naming a window the run was never taken over, which
    /// is worse than a label naming none at all.
    ///
    /// Zero on the `quic` reference leg, whose controller has no such filter,
    /// and on any run recorded before this field existed. `analyze.py` prints
    /// the horizon only when the rows carry one.
    #[serde(default)]
    pub bw_filter_window_ms: u64,
    pub pacing_rate_bps: u64,
    pub min_rtt_us: u64,
    /// Drain passes by the reason each ended, in the transport's own
    /// `DrainOutcome` order: drained, congestion-limited, flow-controlled,
    /// transport-refused, segment-budget, paced. Empty on a leg or a run that
    /// carries none.
    ///
    /// A census the sender kept, where every other reading of "what stopped it"
    /// in this harness is an inference drawn afterwards from the window and the
    /// bytes outstanding. The inference cannot separate a pass the pacer metered
    /// from one that ran dry with the window open — both leave the same window
    /// behind — and those two are the pair the application-limited flag turns on,
    /// so telling them apart decides whether a run's rate describes the path or
    /// the application.
    #[serde(default)]
    pub drain_outcomes: Vec<u64>,
    /// Smoothed round trip and its variation, in microseconds, beside the
    /// minimum. Zero on a leg or a run that carries neither.
    ///
    /// The minimum alone cannot price a delay, and a run needed it to: the split
    /// below can say a quarter of a sender's repairs were ordered by the
    /// retransmission timer rather than the packet threshold, and the interval
    /// between those two is `4 · rtt_variation_us` — tens of milliseconds or
    /// hundreds, which are different findings about the same run.
    #[serde(default)]
    pub smoothed_rtt_us: u64,
    /// See [`Self::smoothed_rtt_us`].
    #[serde(default)]
    pub rtt_variation_us: u64,
    pub delivered_bytes: u64,
    /// BBR phase: startup / drain / probe_bw / probe_rtt. Loss does not move
    /// this — it is answered by a bound on inflight, which is
    /// [`Self::inflight_hi_bytes`] below.
    pub state: String,
    /// True when the window had room and there was nothing to send — the
    /// application was the limit, not the transport.
    pub app_limited: bool,
    /// Bytes the sender has retransmitted, cumulative — every copy its loss
    /// detector ordered, counting the second and third copies of a segment as
    /// well as the first.
    ///
    /// **The row carried no loss quantity at all until this, and that is why one
    /// question could not be answered from an archive.** A run whose window
    /// series shows the loss bound engaged says the sender backed off; it does
    /// not say what it backed off *from*, or what the backing off cost. Together
    /// with [`Self::bytes_lost`] it now does: that one counts holes, this one
    /// counts copies, and the difference is the bandwidth that went into
    /// re-repairing segments whose first copy also failed to arrive.
    ///
    /// **Neither figure separates drops from reordering, and no column here
    /// can.** RFC 9002's packet threshold declares a segment lost once three of
    /// its successors are acknowledged, which is what a path that reorders
    /// produces without having dropped anything, and the sender never learns
    /// which happened — an acknowledgement on this wire names the segment's
    /// stream offset, which the original and every copy shared. The reference
    /// route's own raw controls show reordering at 0.48% with displacements up
    /// to 225 datagrams, so on that route `bytes_lost` is an **upper bound** on
    /// the drops and should be read as one.
    ///
    /// Defaulted on deserialize, so runs recorded before these fields existed
    /// load as zeros rather than failing to parse. Zero on the `quic` leg, whose
    /// controller does not expose the figure.
    #[serde(default)]
    pub bytes_retransmitted: u64,
    /// Bytes of hole the sender fed to congestion control, cumulative — one
    /// booking per segment it first put a copy of on the wire. The numerator of
    /// the round loss rate the inflight bound is judged on.
    #[serde(default)]
    pub bytes_lost: u64,
    /// Holes declared, one per segment the sender first ordered a copy of — the
    /// count [`Self::bytes_lost`] is the byte weight of.
    ///
    /// The row carried the weight and not the count, and they are different
    /// findings: two megabytes of holes at 1156 bytes each is a different path
    /// from two megabytes at two hundred.
    #[serde(default)]
    pub loss_declarations: u64,
    /// Copies whose ordering rule was recorded — the denominator of the three arm
    /// counters below, and **not** the same population as
    /// [`Self::loss_declarations`]: a hole is counted once however many copies
    /// repairing it took, while every copy is attributed. One of the three rules
    /// can only fire on a segment with no copy on the wire, so attributing per
    /// hole would have fixed its share by construction rather than measuring it.
    #[serde(default)]
    pub repairs_attributed: u64,
    /// Of those copies, the ones the packet threshold ordered — successors of a
    /// segment were acknowledged and it was not.
    ///
    /// This is the arm an overtaken datagram satisfies without anything having
    /// been dropped, so a run whose repairs sit here while its raw controls
    /// report no reordering is saying its holes were drops. Sums with
    /// [`Self::declared_by_time_threshold`] and [`Self::declared_by_rto`] to more
    /// than [`Self::repairs_attributed`] by the number of copies both threshold
    /// arms ordered.
    #[serde(default)]
    pub declared_by_packet_threshold: u64,
    /// Of those copies, the ones RACK's time threshold ordered — the segment aged
    /// past `srtt·9/8` since its latest transmission, with an acknowledgement having
    /// moved past it.
    #[serde(default)]
    pub declared_by_time_threshold: u64,
    /// Of those, the ones the retransmission timer ordered against a peer that
    /// had acknowledged nothing — the backstop underneath the other two, and the
    /// only arm no acknowledgement takes part in.
    #[serde(default)]
    pub declared_by_rto: u64,
    /// The loss-imposed bound on bytes outstanding, or `0` when the path has
    /// given no reason for one.
    ///
    /// Recorded rather than inferred, and the reason is a reading this harness
    /// has already had to make by hand: the bound is applied inside the window
    /// calculation, so from the outside its engagement can only be guessed at by
    /// comparing `cwnd_bytes` against `bottleneck_bw_bps × min_rtt_us` — and
    /// that guess misreads exactly the states worth reading. ProbeRTT pins the
    /// window to four packets for reasons of its own, and a bound set while the
    /// estimate was smaller stays a fixed byte count while the product it is
    /// compared against keeps growing, so the ratio drops below the floor the
    /// bound is supposed to respect. Zero here is unambiguous.
    #[serde(default)]
    pub inflight_hi_bytes: u64,
}

/// One rung of the byte-ceiling sweep: a saturating transfer at one frame size,
/// and where the bytes outstanding settled.
///
/// A saturated sender can be sitting against either of two byte ceilings — the
/// ARQ send buffer or the peer's advertised flow-control window — and at the
/// frame size the rest of the matrix runs at they are within half a percent of
/// each other, so no field of a [`WindowSample`] tells them apart. They differ
/// in **units**: the buffer is bounded in segments, so its byte figure moves
/// with the frame size, and the window is bounded in bytes and does not. Moving
/// the frame is therefore the only thing that separates them, and this record is
/// one such rung.
///
/// Both candidates travel in the record beside the measurement, with the library
/// constants they were computed from. That is deliberate and is the same bargain
/// as [`WindowSample::bw_filter_window_ms`]: a reading whose bounds are held in
/// an analysis script goes wrong silently the day a constant moves, and the
/// failure mode is a confident label naming a bound the run was never taken
/// against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendCeilingSample {
    pub leg: Leg,
    pub t_unix_ns: u64,
    /// Index into the sweep, so rungs stay ordered after any sort.
    pub rung: u16,
    /// Application bytes per frame the rung was driven at.
    pub frame_bytes: u32,
    /// What one such frame cost on the wire — the unit both ceilings are in.
    pub wire_frame_bytes: u32,
    /// Segments of the ARQ send buffer one frame occupies.
    pub segments_per_frame: u32,
    /// `transport::stream::MAX_PENDING_PACKETS` as this build has it.
    pub send_buffer_segments: u32,
    /// `transport::mtu::MAX_APP_CHUNK` as this build has it.
    pub app_chunk_bytes: u32,
    /// The two candidate ceilings at this frame size, in bytes. The lower of
    /// the two is the one that can bind; whether the sender actually reached it
    /// is what the rung measures.
    pub arq_buffer_bytes: u64,
    /// `transport::stream::MAX_SEND_WINDOW`, read from the library rather than
    /// restated.
    pub peer_window_bytes: u64,
    pub window_ns: u64,
    pub client_bytes: u64,
    pub client_frames: u64,
    pub megabits_per_sec: f64,
    /// What the server counted, which is the honest figure — `None` when its
    /// report never came back.
    pub server_bytes: Option<u64>,
    pub server_frames: Option<u64>,
    /// Congestion-window samples taken over the rung, and how many of them the
    /// tail statistics below were drawn from.
    ///
    /// The tail is where a saturated sender sits: the head of any transfer is
    /// the controller climbing, and a distribution over the whole of it
    /// describes the climb rather than the ceiling.
    pub window_samples: usize,
    pub tail_samples: usize,
    pub tail_share: f64,
    /// Bytes outstanding over that tail, and the congestion window beside it —
    /// a window that never rose above the ceiling means the rung never put the
    /// question, whatever the outstanding bytes did.
    pub inflight_tail: Summary,
    pub cwnd_tail: Summary,
    /// The session refused a frame for longer than an operation budget, so the
    /// rung ended on backpressure rather than on its own clock.
    pub stalled: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputSample {
    pub leg: Leg,
    pub direction: String,
    pub t_unix_ns: u64,
    /// Rolling 1-second window observation, so a stall shows up as a hole in
    /// the series rather than being averaged away by the run-level total.
    pub window_bytes: u64,
    pub window_frames: u64,
    pub window_ns: u64,
    pub cumulative_bytes: u64,
}

/// One transfer counted from both ends: what the sender handed the API, and
/// what the receiving side actually took in.
///
/// `send()` buffers, so a sending side's own per-window counts say how full its
/// own buffer got and not what crossed the path. On an upload the arriving side
/// is the server, and its count reached a reader only as a sentence in the
/// scenario's notes — prose no analysis can divide by, which is how the leg
/// comparison came to publish a client-side number for a direction whose honest
/// figure is the server's. These are the same numbers as fields.
///
/// Both books travel in one record, for the reason [`RungSample`] carries the
/// sender's account beside the receiver's: the pair *is* the reading. The
/// sender's figure alone is what was offered, the receiver's alone has no
/// offered rate to be read against, and joining them after the fact means
/// matching two files on a timestamp.
///
/// The three server fields are optional together. A transfer whose closing
/// report never came back still writes a receipt, with those three absent and
/// `error` saying which half failed; zeros there would say "nothing arrived",
/// which is a different fact from "nobody counted". A run that has no receipt
/// file at all is a third thing again — one recorded before this existed.
///
/// Only the upload direction writes one. On a download the arriving side is the
/// client, whose own sampling windows are already the honest figure, so there is
/// no second book to fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferReceiptSample {
    pub leg: Leg,
    pub direction: String,
    pub t_unix_ns: u64,
    /// What the client handed the session, in the client's own units: wire
    /// bytes, meaning payload plus this harness's frame header.
    pub client_bytes: u64,
    pub client_frames: u64,
    /// The interval the client drove the burst over, from its own clock.
    pub client_window_ns: u64,
    /// Payload bytes the server decrypted and counted — payload only, so the
    /// two byte figures differ by one frame header each and are not subtractable
    /// without it.
    pub server_bytes: Option<u64>,
    pub server_frames: Option<u64>,
    /// First arrival to last arrival at the server: its own observation span,
    /// which excludes the connect and the client's start-up. This is the
    /// denominator the honest rate is taken over, and it is not the client's
    /// window — the two differ by whatever was still in flight at each end.
    pub server_observed_ns: Option<u64>,
    /// Why the server's side is absent, when it is. Absent for a receipt that
    /// has one.
    pub error: Option<String>,
}

impl TransferReceiptSample {
    /// A transfer whose closing report came back, with what the server counted.
    pub fn counted(
        leg: Leg,
        direction: &str,
        client: &Throughput,
        server_frames: u64,
        server_bytes: u64,
        server_observed_ns: u64,
    ) -> Self {
        Self {
            server_bytes: Some(server_bytes),
            server_frames: Some(server_frames),
            server_observed_ns: Some(server_observed_ns),
            error: None,
            ..Self::skeleton(leg, direction, client)
        }
    }

    /// A transfer whose closing report did not come back, and why.
    ///
    /// Written rather than omitted: a missing file says the run predates the
    /// receipt entirely, and that is a different thing from a run that tried to
    /// count and could not. An analysis that cannot tell them apart has to
    /// describe both in the words of whichever it guessed.
    pub fn uncounted(leg: Leg, direction: &str, client: &Throughput, why: &str) -> Self {
        Self {
            server_bytes: None,
            server_frames: None,
            server_observed_ns: None,
            error: Some(why.to_string()),
            ..Self::skeleton(leg, direction, client)
        }
    }

    fn skeleton(leg: Leg, direction: &str, client: &Throughput) -> Self {
        Self {
            leg,
            direction: direction.to_string(),
            t_unix_ns: unix_nanos(),
            client_bytes: client.bytes,
            client_frames: client.frames,
            client_window_ns: client.duration_ns,
            server_bytes: None,
            server_frames: None,
            server_observed_ns: None,
            error: None,
        }
    }
}

/// One rung of a raw UDP capacity ladder, recorded from both ends.
///
/// The fields exist in pairs on purpose. A rung has an *offered* rate, a rate
/// the sender actually achieved on its own socket, and a rate the receiver
/// observed; collapsing those into one number is how a control comes to report
/// its own scheduler as the path's ceiling. So the sender's account travels
/// with the receiver's, and [`Self::sender_reached_offer`] states in a field —
/// not in prose — whether the rung is admissible as evidence at all.
///
/// One record shape carries all three ladders — the round-trip echo and the two
/// one-way controls — and [`Self::direction`] is what tells them apart. That is
/// deliberate: the uplink and downlink numbers are read side by side, and a
/// second record shape would be a second set of definitions to keep in step.
/// Which end is local differs between them and nothing else does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RungSample {
    pub leg: Leg,
    /// `raw_udp_downstream` (server → client), `raw_udp_upstream`
    /// (client → server), or `raw_udp_echo_roundtrip` — no protocol in the way
    /// in any of them.
    pub direction: String,
    pub t_unix_ns: u64,
    /// Index into the ladder, so rungs stay ordered after any sort.
    pub rung: u16,
    pub offered_bps: f64,
    pub payload_bytes: usize,
    /// Interval the rung was asked to run for.
    pub requested_ns: u64,

    /// Datagrams the sender says it put on its own socket. `None` when its
    /// report never arrived, which makes every derived figure below unanchored
    /// and is why they are optional too.
    pub sender_datagrams: Option<u64>,
    pub sender_bytes: Option<u64>,
    pub sender_elapsed_ns: Option<u64>,
    pub sender_bps: Option<f64>,
    /// False when the sender fell short of its own offer. Such a rung measures
    /// the sender, not the path, and the analysis filters on this field.
    pub sender_reached_offer: Option<bool>,

    pub received_datagrams: u64,
    pub received_bytes: u64,
    /// Arrived after a higher-numbered datagram already had.
    pub reordered_datagrams: u64,
    pub duplicate_datagrams: u64,
    /// How far back, and how long after, those late datagrams came — plus the
    /// gap-by-gap split of reordering from loss.
    ///
    /// The count above says the path reorders; it sizes nothing, because a
    /// transport's reordering tolerance is a distance and a duration. This is
    /// the distribution of both. Defaulted on deserialize so runs recorded
    /// before it existed still load.
    #[serde(default)]
    pub reorder: crate::downlink::ReorderProfile,

    /// First arrival to last arrival — the receiver's own observation interval,
    /// which excludes the request's round trip and the sender's start-up.
    pub observed_window_ns: u64,
    pub receiver_bps: f64,
    /// `None` without the sender's count: a gap at the receiver is
    /// indistinguishable from a datagram never sent.
    pub loss_fraction: Option<f64>,

    /// True only when the sender reached its offer and enough arrived to
    /// measure an interval. The one field to filter on before quoting a rung as
    /// the path's capacity.
    pub admissible: bool,
    /// Why not, when `admissible` is false.
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroRttSample {
    pub seq: u64,
    pub leg: Leg,
    pub t_unix_ns: u64,
    pub cold_connect_ns: Option<u64>,
    pub resumed_connect_ns: Option<u64>,
    pub early_data_accepted: Option<bool>,
    pub got_hint: bool,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationSample {
    pub seq: u64,
    pub leg: Leg,
    pub t_unix_ns: u64,
    pub old_local_addr: Option<String>,
    pub new_local_addr: String,
    /// Wall time the `migrate()` call itself took.
    pub migrate_call_ns: Option<u64>,
    /// Gap between the last frame before migration and the first after — the
    /// number a user would perceive as a freeze.
    pub data_gap_ns: Option<u64>,
    /// Round trips that failed while the path was being revalidated.
    pub failed_rtts: u64,
    pub recovered: bool,
    pub state_after: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSample {
    pub leg: Leg,
    pub stream_id: u32,
    pub priority: u32,
    pub t_unix_ns: u64,
    pub seq: u64,
    pub rtt_ns: Option<u64>,
    pub bytes: usize,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakSample {
    pub leg: Leg,
    pub t_unix_ns: u64,
    pub elapsed_s: u64,
    pub state: String,
    pub rtt_ns: Option<u64>,
    pub ok: bool,
    pub error: Option<String>,
    pub metrics: Option<ClientMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencySample {
    pub leg: Leg,
    pub session_index: usize,
    pub t_unix_ns: u64,
    pub connect_ns: Option<u64>,
    pub rtt_ns: Option<u64>,
    pub ops: u64,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeSample {
    pub case: String,
    pub leg: Leg,
    pub t_unix_ns: u64,
    pub expected: String,
    pub observed: String,
    /// Whether the observed behaviour matched what the protocol promises.
    /// A `false` here is a finding, not a test-harness failure.
    pub passed: bool,
    pub elapsed_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeySample {
    pub leg: Leg,
    pub seq: u64,
    pub t_unix_ns: u64,
    pub rtt_ns: Option<u64>,
    pub bytes_sent: u64,
    pub ok: bool,
    pub error: Option<String>,
}

/// One run of the wire-level encryption check.
///
/// The record deliberately keeps three different kinds of statement apart. The
/// `findings` are what a packet capture established. The `session_counters` are
/// what the session's own instruments reported over the same interval — related
/// evidence, but from a different instrument. And `findings.encrypted_flag` is
/// not a measurement at all: it is the part of security invariant 2 that a
/// capture cannot reach, answered from the source and labelled as such. Folding
/// any two of those together is exactly how the claim would come to be
/// overstated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireCheckSample {
    pub leg: Leg,
    pub t_unix_ns: u64,
    /// When the session reported itself established. This is the instant that
    /// splits the capture into its handshake and established halves, and it
    /// comes from the same host clock the capture is stamped with.
    pub established_unix_ns: u64,
    /// Application messages the probe generated and then searched for.
    pub probe_messages: usize,
    pub probe_payload_bytes: usize,
    pub echo_ok: usize,
    pub echo_failed: usize,
    /// The capture command, verbatim, so the evidence can be reproduced by hand.
    pub capture_command: String,
    /// Where the capture was kept. `None` when none was taken.
    pub capture_path: Option<String>,
    pub findings: crate::wirecheck::Findings,
    /// The session's own counters at the end of the exchange.
    ///
    /// Three of them are security numbers: `replay_rejected_total`,
    /// `aead_failure_total`, and `unencrypted_dropped_total`. The last is the
    /// only run-time evidence that the `ENCRYPTED` gate ran at all — a refused
    /// packet is otherwise indistinguishable from one that never arrived, and a
    /// capture cannot see the flag either way.
    pub session_counters: Option<ClientMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRecord {
    pub t_unix_ns: u64,
    pub leg: Option<Leg>,
    pub scenario: String,
    pub context: String,
    pub error: String,
    pub error_kind: String,
    /// How long the operation that failed had been running, where the caller
    /// could measure it.
    ///
    /// Load-bearing for one error kind in particular. A `Timeout` on a Phantom
    /// connect can come from any of three independent timers — the UDP
    /// transport's handshake-retransmission budget, the session's whole-handshake
    /// deadline, or this harness's own `CONNECT_TIMEOUT` around `await_ready()` —
    /// and they mean three different things: the transport gave up after
    /// retransmitting its flight, the session gave up while the transport was
    /// still trying, or the harness gave up on a session that had not yet
    /// reported either way. `t_unix_ns` alone dates the failure without naming
    /// which of them produced it, and separating them took reading the library's
    /// constants and correlating against the daemon's clock. The duration says it
    /// outright.
    ///
    /// `None` where the failure has no single operation to time.
    pub elapsed_ns: Option<u64>,
}

/// Client-side view of the session's own counters.
///
/// `Default` is all-zero, which is what the QUIC reference leg reports: these
/// are Phantom's own instruments and no equivalent exists there. A row of zeros
/// under `listener: "quic"` means "not instrumented", not "nothing happened".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientMetrics {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub avg_encrypt_ns: u64,
    pub avg_decrypt_ns: u64,
    pub encrypt_count: u64,
    pub decrypt_count: u64,
    pub rtt_us_path_0: u64,
    pub active_sessions: i64,
    pub active_streams: i64,
    /// Handshakes the **recording side** finished — not connects the other end
    /// joined, and the difference is not a rounding error.
    ///
    /// A listener counts one as soon as it has derived keys and sent its
    /// `ServerHello`, which nothing acknowledges: a reply lost on the way down
    /// leaves a session counted here whose peer never spoke. This run's own
    /// artifacts hold one, at `dur=135.0 s, rx=0, tx=0`, taken from a daemon
    /// reporting 58 successful handshakes while the probe was reporting timeouts.
    /// Read a server total against client failures as two measurements of one
    /// path; the three repair counters below are what say whether the reply was
    /// asked for again and re-sent.
    pub handshakes_success: u64,
    pub handshakes_failure: u64,
    pub handshake_latency_ns_sum: u64,
    pub handshake_latency_count: u64,
    pub replay_rejected_total: u64,
    pub aead_failure_total: u64,
    /// Post-handshake packets refused for arriving without the `ENCRYPTED` flag.
    /// Carried because it is the only externally visible difference between "the
    /// gate refused something" and "nothing arrived" — a capture cannot tell them
    /// apart, since header protection hides the flag it turns on.
    pub unencrypted_dropped_total: u64,
    /// **Datagrams**, not questions: handshake datagrams that arrived for a
    /// connection the listener had already committed a route to, counted before
    /// reassembly.
    ///
    /// A cookie-bearing hello crosses the path in three fragments, so this runs at
    /// roughly 3× the field below it. What it is good for is the duplicate wire load
    /// a repeating client costs the listener — **not** for dividing into
    /// `handshake_flight_repeated_total`, which counts flights and would make a
    /// listener that answered every question look like one that dropped two thirds
    /// of them.
    #[serde(default)]
    pub initial_datagrams_on_committed_route_total: u64,
    /// **Flights**: reassembled handshake messages that arrived for a connection the
    /// listener had already committed a route to — a client asking its question
    /// again, once per question.
    ///
    /// This is the counter a failed connect is read against, and it exists because
    /// the artifact could not answer the question once already: when four connects
    /// timed out on 2026-08-22 it took the server's own session records plus the
    /// library's constants to establish that the reply had been sent and lost,
    /// rather than the request never arriving. A non-zero value here says the
    /// client's repeat reached the listener; the fields below say what it did with it.
    #[serde(default)]
    pub initial_flights_on_committed_route_total: u64,
    /// **Flights**: retained reply flights actually repeated. Read beside
    /// `initial_flights_on_committed_route_total`, which is in the same unit:
    /// asked-and-answered is a repaired connect, asked-and-not-answered is a
    /// connect the retention could not cover, and the two are indistinguishable
    /// without both numbers.
    #[serde(default)]
    pub handshake_flight_repeated_total: u64,
    /// Retained flights dropped to make room. Non-zero means the retention budget
    /// bound during this run, so a connect that failed here may have failed for
    /// want of a repeat rather than for want of a path.
    #[serde(default)]
    pub handshake_flight_evicted_total: u64,
    /// Reply flights never retained, because repeating one would have exceeded the
    /// anti-amplification bound. Those sessions have no repair at all, which is a
    /// property of the parameter set rather than of the run.
    #[serde(default)]
    pub handshake_flight_refused_total: u64,
    pub uptime_secs: u64,
}

impl From<phantom_protocol::observability::MetricsSnapshotFfi> for ClientMetrics {
    fn from(s: phantom_protocol::observability::MetricsSnapshotFfi) -> Self {
        Self {
            packets_sent: s.packets_sent,
            packets_recv: s.packets_recv,
            bytes_sent: s.bytes_sent,
            bytes_recv: s.bytes_recv,
            avg_encrypt_ns: s.avg_encrypt_ns,
            avg_decrypt_ns: s.avg_decrypt_ns,
            encrypt_count: s.encrypt_count,
            decrypt_count: s.decrypt_count,
            rtt_us_path_0: s.rtt_us_path_0,
            active_sessions: s.active_sessions,
            active_streams: s.active_streams,
            handshakes_success: s.handshakes_success,
            handshakes_failure: s.handshakes_failure,
            handshake_latency_ns_sum: s.handshake_latency_ns_sum,
            handshake_latency_count: s.handshake_latency_count,
            replay_rejected_total: s.replay_rejected_total,
            aead_failure_total: s.aead_failure_total,
            unencrypted_dropped_total: s.unencrypted_dropped_total,
            initial_datagrams_on_committed_route_total: s
                .initial_datagrams_on_committed_route_total,
            initial_flights_on_committed_route_total: s.initial_flights_on_committed_route_total,
            handshake_flight_repeated_total: s.handshake_flight_repeated_total,
            handshake_flight_evicted_total: s.handshake_flight_evicted_total,
            handshake_flight_refused_total: s.handshake_flight_refused_total,
            uptime_secs: s.uptime_secs,
        }
    }
}

// ── Server records ──────────────────────────────────────────────────────────

/// Per-leg packet/byte counters, so the daemon's statistics can be read leg by leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerLegCounters {
    pub leg: String,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub listener: String,
    pub t_unix_ns: u64,
    /// The daemon's own build. Carried on every snapshot and every `STATS`
    /// reply because this is the only channel by which the probe can learn
    /// which code was on the other end of its measurements.
    pub build: BuildId,
    pub metrics: ClientMetrics,
    pub per_leg: Vec<PerLegCounters>,
    pub process: ProcInfo,
    /// The server's own congestion-control state for this session. During a
    /// download the server is the sender, so this — not the client's series —
    /// is the window that governs the transfer.
    pub sender_window: Option<WindowSample>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcInfo {
    pub rss_kb: u64,
    pub vm_size_kb: u64,
    pub threads: u64,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub open_fds: u64,
    pub load1: f64,
    pub load5: f64,
    pub mem_available_kb: u64,
    pub uptime_s: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_uid: u64,
    pub listener: String,
    pub peer: String,
    pub t_open_unix_ns: u64,
    pub t_close_unix_ns: u64,
    pub duration_ns: u64,
    pub early_data_bytes: usize,
    pub had_early_data: bool,
    pub frames_recv: u64,
    pub frames_sent: u64,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
    pub echo_frames: u64,
    pub sink_frames: u64,
    pub source_frames: u64,
    pub streams_accepted: u64,
    /// Logical messages the server had to reassemble from more than one
    /// `PhantomSession::recv()` result — the session split them in transit.
    pub split_messages: u64,
    /// Congestion-window sweeps this session recorded into `windows.jsonl`.
    ///
    /// The series there is keyed on `server:session:<uid>`, so its rows can be
    /// counted directly — but rows only ever account for sweeps that produced a
    /// sample. Comparing them against this figure is what separates a sample
    /// the sampler never took from one the collector dropped under load: two
    /// different faults that look identical in the file.
    pub window_samples: u64,
    /// Sweeps that produced nothing, because the sender had no window estimate
    /// to describe at that instant.
    ///
    /// This is the field that keeps a short series readable: rows present plus
    /// this count is every sweep the sampler ran, so "there was nothing to
    /// record" and "what was recorded is gone" stop being the same absence. It
    /// belongs on the session record rather than in `snapshots.jsonl` because
    /// the sampler is per-session — the periodic listener sweep could only
    /// report a sum across sessions, and that sum is exactly the attribution
    /// that was missing.
    pub window_samples_skipped: u64,
    pub marks: Vec<MarkRecord>,
    pub close_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkRecord {
    pub t_unix_ns: u64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub t_unix_ns: u64,
    pub listener: String,
    pub kind: String,
    pub peer: Option<String>,
    pub session_uid: Option<u64>,
    pub detail: String,
}

// ── Summary ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioSummary {
    pub leg: Leg,
    pub scenario: String,
    pub ok_count: usize,
    pub error_count: usize,
    pub latency_ns: Option<Summary>,
    pub throughput: Option<Throughput>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub profile: String,
    pub scenarios: Vec<ScenarioSummary>,
}

// ── In-memory sample sink ───────────────────────────────────────────────────

/// Accumulates serialized sample lines in memory, then writes them once.
///
/// The push path is a `format!` plus a `Vec::push` — no syscall — so recording
/// a sample cannot perturb the latency it is recording.
pub struct SampleSink {
    lines: Vec<String>,
}

impl Default for SampleSink {
    fn default() -> Self {
        Self::new()
    }
}

impl SampleSink {
    pub fn new() -> Self {
        Self {
            lines: Vec::with_capacity(1024),
        }
    }

    pub fn push<T: Serialize>(&mut self, rec: &T) {
        match serde_json::to_string(rec) {
            Ok(s) => self.lines.push(s),
            // A sample that will not serialize is a harness bug; record it in
            // band rather than dropping it silently, so the gap is visible in
            // the artifact.
            Err(e) => self.lines.push(format!(
                r#"{{"_serialize_error":"{}"}}"#,
                escape(&e.to_string())
            )),
        }
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The serialized records as they will be written.
    ///
    /// Read-only, and here so a test can assert on the record a scenario
    /// actually emitted rather than on a value it built by hand — the two
    /// differ exactly where a scenario fills a field wrongly, which is the
    /// case worth catching.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Write every accumulated line to `path`, creating parent directories.
    pub fn write_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        let mut w = BufWriter::new(f);
        for line in &self.lines {
            w.write_all(line.as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ── Rotating JSONL writer (server side) ─────────────────────────────────────

/// Append-only JSONL writer with size-based rotation.
///
/// Rotation keeps a multi-hour soak from filling the volume: at the cap the
/// current file becomes `<name>.1` (replacing any previous `.1`) and a fresh
/// file opens. Exactly one generation is retained — enough to survive a
/// rotation landing mid-run, without unbounded growth.
pub struct JsonlWriter {
    inner: Mutex<Inner>,
}

struct Inner {
    path: PathBuf,
    file: BufWriter<File>,
    written: u64,
    max_bytes: u64,
}

impl JsonlWriter {
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            inner: Mutex::new(Inner {
                path,
                file: BufWriter::new(file),
                written,
                max_bytes,
            }),
        })
    }

    pub fn write<T: Serialize>(&self, rec: &T) -> std::io::Result<()> {
        let line = serde_json::to_string(rec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // Poison recovery rather than propagation: a panic in another writer
        // must not permanently wedge the collector for the rest of the run.
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.written + line.len() as u64 + 1 > g.max_bytes {
            g.rotate()?;
        }
        g.file.write_all(line.as_bytes())?;
        g.file.write_all(b"\n")?;
        g.written += line.len() as u64 + 1;
        Ok(())
    }

    pub fn flush(&self) -> std::io::Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.file.flush()
    }
}

impl Inner {
    fn rotate(&mut self) -> std::io::Result<()> {
        self.file.flush()?;
        let rotated = self.path.with_extension("jsonl.1");
        // Best-effort: if the rename fails (read-only mount, race) keep writing
        // to the current file rather than losing the record entirely.
        let _ = std::fs::rename(&self.path, &rotated);
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.file = BufWriter::new(f);
        self.written = 0;
        Ok(())
    }
}

impl Drop for JsonlWriter {
    fn drop(&mut self) {
        if let Ok(mut g) = self.inner.lock() {
            let _ = g.file.flush();
        }
    }
}

/// Write a value as pretty JSON, creating parent directories.
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let s = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_conversion_matches_known_epochs() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        // 2000-03-01 is day 11017 — exercises the leap-century branch.
        assert_eq!(civil_from_days(11017), (2000, 3, 1));
        assert_eq!(civil_from_days(19723), (2024, 1, 1));
        // 2024 is a leap year: Feb 29 must exist.
        assert_eq!(civil_from_days(19782), (2024, 2, 29));
    }

    #[test]
    fn utc_stamp_has_the_expected_shape() {
        let s = utc_stamp();
        assert_eq!(s.len(), 20, "{s}");
        assert!(s.ends_with('Z'));
        assert_eq!(s.as_bytes()[10], b'T');
    }

    #[test]
    fn run_id_is_filesystem_safe() {
        let id = run_id_stamp();
        assert!(
            id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "run id must be path-safe: {id}"
        );
        assert_eq!(id.len(), 15, "{id}");
    }

    /// The JSON token, the CLI token, and the directory name must be one
    /// string. They live in three different attributes, so nothing but a test
    /// keeps them from drifting apart again.
    #[test]
    fn leg_serialises_exactly_as_it_names_its_directory() {
        for leg in [
            Leg::Udp,
            Leg::Tcp,
            Leg::Mimic,
            Leg::Quic,
            Leg::RawTcp,
            Leg::RawUdp,
        ] {
            let json = serde_json::to_string(&leg).expect("serialize");
            assert_eq!(
                json,
                format!("\"{}\"", leg.as_str()),
                "serde token must equal as_str() for {leg:?}"
            );
            let back: Leg = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, leg, "round-trip must be lossless");
            assert_eq!(leg.to_string(), leg.as_str());
        }
        // Pin the exact spellings so a rename shows up here rather than in a
        // half-broken data set.
        assert_eq!(Leg::RawTcp.as_str(), "raw_tcp");
        assert_eq!(Leg::RawUdp.as_str(), "raw_udp");
        assert_eq!(Leg::Quic.as_str(), "quic");
    }

    #[test]
    fn leg_properties() {
        assert!(Leg::Udp.supports_migration());
        assert!(!Leg::Tcp.supports_migration());
        assert!(!Leg::Mimic.supports_migration());
        assert!(!Leg::Quic.supports_migration());
        assert!(Leg::Udp.is_phantom() && Leg::Tcp.is_phantom() && Leg::Mimic.is_phantom());
        assert!(!Leg::RawTcp.is_phantom() && !Leg::RawUdp.is_phantom());

        // The reference leg is neither the protocol under test nor a raw
        // control: mixing it into either bucket would put a QUIC number under a
        // Phantom heading, or drop it from the comparison entirely.
        assert!(
            !Leg::Quic.is_phantom(),
            "QUIC is not the protocol under test"
        );
        assert!(Leg::Quic.is_reference());
        for other in [Leg::Udp, Leg::Tcp, Leg::Mimic, Leg::RawTcp, Leg::RawUdp] {
            assert!(!other.is_reference(), "{other} is not a reference leg");
        }
    }

    /// A client-side throughput figure, of the shape an upload burst produces.
    fn client_book() -> Throughput {
        Throughput::new(3_100_000, 3100, 12_000_000_000)
    }

    /// The honest upload rate has to be computable from the record's own fields,
    /// which is the whole reason the record exists: it was already stated in
    /// prose, and prose is not a denominator.
    #[test]
    fn a_counted_receipt_yields_the_server_observed_rate_without_prose() {
        let r = TransferReceiptSample::counted(
            Leg::Udp,
            "upload",
            &client_book(),
            3059,
            3_059_210,
            12_476_000_000,
        );

        let bytes = r.server_bytes.expect("counted");
        let span = r.server_observed_ns.expect("counted");
        let bps = bytes as f64 * 8.0 / (span as f64 / 1e9);
        assert!(
            (bps / 1e6 - 1.961).abs() < 0.01,
            "server-observed rate must fall out of the fields: {bps}"
        );
        assert_eq!(r.server_frames, Some(3059));
        assert!(r.error.is_none());

        // And the sending side's own book travels beside it, so the record is
        // one reading rather than half of one waiting on a join. The two differ
        // here by exactly what buffering hides, which is the point.
        assert_eq!(r.client_bytes, 3_100_000);
        assert_eq!(r.client_frames, 3100);
        assert_eq!(r.client_window_ns, 12_000_000_000);
    }

    /// Absent and zero are different statements. A transfer nobody counted must
    /// not read as a transfer where nothing arrived — the second is a finding
    /// and the first is a gap in the instrument.
    #[test]
    fn an_uncounted_receipt_says_nobody_counted_rather_than_nothing_arrived() {
        let r = TransferReceiptSample::uncounted(
            Leg::Tcp,
            "upload",
            &client_book(),
            "sink_end sent, no report: Timeout",
        );

        assert_eq!(r.server_bytes, None);
        assert_eq!(r.server_frames, None);
        assert_eq!(r.server_observed_ns, None);
        assert!(
            r.error.as_deref().unwrap_or_default().contains("no report"),
            "the reason has to travel with the gap: {:?}",
            r.error
        );
        // The client's book is still recorded: it is the only figure such a run
        // has, and dropping the row would leave the leg out of the comparison
        // entirely.
        assert_eq!(r.client_bytes, 3_100_000);
    }

    /// The three server fields are one fact and have to be optional together —
    /// two of three would let an analysis compute a rate over a span nobody
    /// measured.
    #[test]
    fn the_server_side_of_a_receipt_is_present_or_absent_as_a_whole() {
        for r in [
            TransferReceiptSample::counted(Leg::Udp, "upload", &client_book(), 1, 2, 3),
            TransferReceiptSample::uncounted(Leg::Udp, "upload", &client_book(), "why"),
        ] {
            let present = [
                r.server_bytes.is_some(),
                r.server_frames.is_some(),
                r.server_observed_ns.is_some(),
            ];
            assert!(
                present.iter().all(|p| *p) || present.iter().all(|p| !*p),
                "the server's three fields disagreed: {present:?}"
            );
            // `error` is the converse of them: exactly one of the two states.
            assert_eq!(r.error.is_some(), !present[0]);
        }
    }

    /// The reader that opens this file joins on `leg` and `direction`, and the
    /// absent server side has to arrive as JSON null rather than as a missing
    /// key — a missing key and a zero are what the record exists to separate.
    #[test]
    fn a_receipt_serialises_with_its_absences_visible() {
        let v: serde_json::Value = serde_json::to_value(TransferReceiptSample::uncounted(
            Leg::Mimic,
            "upload",
            &client_book(),
            "sink_end send blocked: Timeout",
        ))
        .expect("serialize");

        assert_eq!(v["leg"], "mimic");
        assert_eq!(v["direction"], "upload");
        assert!(v["server_bytes"].is_null(), "{v}");
        assert!(v["server_frames"].is_null(), "{v}");
        assert!(v["server_observed_ns"].is_null(), "{v}");
        assert_eq!(v["client_bytes"], 3_100_000u64);

        let back: TransferReceiptSample =
            serde_json::from_value(v).expect("a receipt must round-trip");
        assert_eq!(back.server_bytes, None);
        assert_eq!(back.client_frames, 3100);
    }

    #[test]
    fn sample_sink_writes_one_json_object_per_line() {
        let dir = std::env::temp_dir().join(format!("tb-sink-{}", std::process::id()));
        let path = dir.join("s.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut sink = SampleSink::new();
        assert!(sink.is_empty());
        for i in 0..3u64 {
            sink.push(&RttSample {
                seq: i,
                leg: Leg::Udp,
                payload_bytes: 64,
                t_unix_ns: 1,
                rtt_ns: 100 + i,
                server_recv_unix_ns: None,
                server_send_unix_ns: None,
                server_turnaround_ns: None,
            });
        }
        assert_eq!(sink.len(), 3);
        sink.write_to(&path).expect("write");

        let body = std::fs::read_to_string(&path).expect("read back");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3);
        for (i, l) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(l).expect("each line is valid JSON");
            assert_eq!(v["seq"], i as u64);
            assert_eq!(v["leg"], "udp");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsonl_writer_rotates_at_the_cap_and_keeps_one_generation() {
        let dir = std::env::temp_dir().join(format!("tb-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("events.jsonl");

        // Cap chosen so a handful of records forces at least one rotation.
        let w = JsonlWriter::open(&path, 200).expect("open");
        for i in 0..40 {
            w.write(&EventRecord {
                t_unix_ns: i,
                listener: "udp".into(),
                kind: "test".into(),
                peer: None,
                session_uid: None,
                detail: "xxxxxxxxxxxxxxxx".into(),
            })
            .expect("write");
        }
        w.flush().expect("flush");
        drop(w);

        assert!(path.exists(), "current generation exists");
        assert!(
            dir.join("events.jsonl.1").exists(),
            "one rotated generation is retained"
        );
        let cur = std::fs::read_to_string(&path).expect("read current");
        assert!(
            cur.len() <= 400,
            "current generation stays bounded, got {}",
            cur.len()
        );
        for l in cur.lines() {
            serde_json::from_str::<serde_json::Value>(l).expect("rotation never splits a record");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The build stamp is what lets an analysis prove two runs used different
    /// code, so it must be present and well-formed in every binary this crate
    /// produces — including one built outside a repository.
    #[test]
    fn the_build_identity_is_always_populated() {
        let b = BuildId::current();
        assert!(
            !b.git_sha.is_empty(),
            "an empty SHA is worse than 'unknown'"
        );
        assert_eq!(b.version, env!("CARGO_PKG_VERSION"));
        if b.git_sha == "unknown" {
            assert!(
                !b.git_dirty,
                "a build with no repository cannot know it is dirty"
            );
        } else {
            assert_eq!(b.git_sha.len(), 40, "full object id: {}", b.git_sha);
            assert!(b.git_sha.chars().all(|c| c.is_ascii_hexdigit()));
        }
        assert!(b.label().starts_with(&b.git_sha));
        let dirty = BuildId {
            git_sha: "abc".into(),
            git_dirty: true,
            version: "0".into(),
        };
        assert_eq!(dirty.label(), "abc-dirty");
    }

    /// The record the downstream control emits, in full, so a change to the
    /// schema shows up here rather than in a Python traceback an hour into a
    /// run's analysis.
    #[test]
    fn a_downstream_rung_serialises_with_every_field_the_analysis_reads() {
        let s = RungSample {
            leg: Leg::RawUdp,
            direction: "raw_udp_downstream".into(),
            t_unix_ns: 1,
            rung: 3,
            offered_bps: 60e6,
            payload_bytes: 1200,
            requested_ns: 5_000_000_000,
            sender_datagrams: Some(31_250),
            sender_bytes: Some(37_500_000),
            sender_elapsed_ns: Some(5_000_000_000),
            sender_bps: Some(60e6),
            sender_reached_offer: Some(true),
            received_datagrams: 30_000,
            received_bytes: 36_000_000,
            reordered_datagrams: 12,
            duplicate_datagrams: 0,
            reorder: crate::downlink::ReorderProfile {
                horizon: 4096,
                late_datagrams: 12,
                distance: Summary::of_u64(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
                displacement_ns: Summary::of_u64(&[1_000_000; 12]),
                transit_excess_ns: Summary::of_u64(&[2_000_000; 12]),
                gaps_filled: 12,
                gaps_lost: 340,
                gaps_open_at_end: 3,
                gaps_beyond_horizon: 0,
                late_beyond_horizon: 0,
            },
            observed_window_ns: 5_000_000_000,
            receiver_bps: 57.6e6,
            loss_fraction: Some(0.04),
            admissible: true,
            note: String::new(),
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&s).expect("encode")).expect("decode");
        assert_eq!(v["leg"], "raw_udp");
        assert_eq!(v["direction"], "raw_udp_downstream");
        assert_eq!(v["rung"], 3);
        assert_eq!(v["offered_bps"], 60e6);
        assert_eq!(v["sender_bps"], 60e6);
        assert_eq!(v["sender_reached_offer"], true);
        assert_eq!(v["receiver_bps"], 57.6e6);
        assert_eq!(v["received_datagrams"], 30_000);
        assert_eq!(v["reordered_datagrams"], 12);
        assert_eq!(v["duplicate_datagrams"], 0);
        assert_eq!(v["observed_window_ns"], 5_000_000_000u64);
        assert_eq!(v["loss_fraction"], 0.04);
        assert_eq!(v["admissible"], true);
        // The distribution, not just the count: an analysis that reads only
        // `reordered_datagrams` cannot size a reordering tolerance.
        assert_eq!(v["reorder"]["horizon"], 4096);
        assert_eq!(v["reorder"]["distance"]["p50"], 6.0);
        assert_eq!(v["reorder"]["distance"]["p90"], 11.0);
        assert_eq!(v["reorder"]["distance"]["p99"], 12.0);
        assert_eq!(v["reorder"]["distance"]["max"], 12.0);
        assert_eq!(v["reorder"]["displacement_ns"]["p99"], 1_000_000.0);
        assert_eq!(v["reorder"]["transit_excess_ns"]["p99"], 2_000_000.0);
        assert_eq!(v["reorder"]["gaps_filled"], 12);
        assert_eq!(v["reorder"]["gaps_lost"], 340);
        assert_eq!(v["reorder"]["gaps_open_at_end"], 3);

        // A rung with no sender report must serialise its unknowns as null, not
        // as zero: zero would read as "the sender sent nothing", which is a
        // measurement, and the truth is that nothing is known.
        let unknown = RungSample {
            sender_datagrams: None,
            sender_bytes: None,
            sender_elapsed_ns: None,
            sender_bps: None,
            sender_reached_offer: None,
            loss_fraction: None,
            admissible: false,
            note: "no report from the sender".into(),
            ..s
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&unknown).expect("encode"))
                .expect("decode");
        assert!(v["sender_bps"].is_null());
        assert!(v["sender_reached_offer"].is_null());
        assert!(v["loss_fraction"].is_null());
        assert_eq!(v["admissible"], false);
        assert!(!v["note"].as_str().unwrap_or_default().is_empty());
    }

    /// Runs already on disk predate the reorder profile, and re-reading them is
    /// how a "did this change help" question gets answered. A record without
    /// the field must load rather than fail the whole file.
    #[test]
    fn a_rung_recorded_before_the_reorder_profile_still_loads() {
        let old = r#"{"leg":"raw_udp","direction":"raw_udp_downstream","t_unix_ns":1,
            "rung":3,"offered_bps":60000000.0,"payload_bytes":1200,
            "requested_ns":5000000000,"sender_datagrams":31250,"sender_bytes":37500000,
            "sender_elapsed_ns":5000000000,"sender_bps":60000000.0,
            "sender_reached_offer":true,"received_datagrams":30000,
            "received_bytes":36000000,"reordered_datagrams":12,"duplicate_datagrams":0,
            "observed_window_ns":5000000000,"receiver_bps":57600000.0,
            "loss_fraction":0.04,"admissible":true,"note":""}"#;
        let s: RungSample = serde_json::from_str(old).expect("an older rung must load");
        assert_eq!(s.reordered_datagrams, 12);
        assert_eq!(
            s.reorder,
            crate::downlink::ReorderProfile::default(),
            "and its unmeasured profile must read as empty, not as zero reordering"
        );
        assert_eq!(s.reorder.horizon, 0, "a zero horizon marks it unmeasured");
    }

    /// A window row has to name the horizon its filtered maximum was taken
    /// over, because the analysis that reads the row a year later must not have
    /// to remember it.
    ///
    /// The alternative was a copy of the constant in `analyze.py`, and a copy is
    /// only ever right until the constant moves — after which the one line whose
    /// job is to name the statistic names the wrong window, silently and with
    /// full confidence. So the horizon travels in the artifact, and the reader
    /// derives the label from it.
    #[test]
    fn a_window_row_names_the_horizon_its_filtered_maximum_was_taken_over() {
        let row = phantom_leg_window_row();
        assert_ne!(
            row.bw_filter_window_ms, 0,
            "a Phantom-leg row that names no horizon leaves the reader to guess \
             which window `bottleneck_bw_bps` is a maximum over"
        );
        assert_eq!(
            row.bw_filter_window_ms,
            phantom_protocol::transport::bandwidth_estimator::BW_FILTER_WINDOW.as_millis() as u64,
            "the recorded horizon has to be the one the estimator in this binary \
             was built with, not a figure restated beside it"
        );

        let back: WindowSample = serde_json::from_str(
            &serde_json::to_string(&row).expect("a window row must serialize"),
        )
        .expect("and load back");
        assert_eq!(back.bw_filter_window_ms, row.bw_filter_window_ms);
    }

    /// Every archive recorded before the horizon was written down still has to
    /// load — the whole reason a run is kept is that it can be re-read against a
    /// later change.
    ///
    /// Such a row reads zero, which is the signal `analyze.py` turns into a
    /// label that names no window at all. Naming one would be worse: the reader
    /// would be told a horizon nobody recorded.
    #[test]
    fn a_window_row_recorded_before_the_horizon_was_named_still_loads() {
        let old = r#"{"leg":"udp","phase":"upload","t_unix_ns":1,"elapsed_ms":500,
            "cwnd_bytes":401688,"inflight_bytes":120000,"bottleneck_bw_bps":1000000,
            "pacing_rate_bps":1000000,"min_rtt_us":235000,"delivered_bytes":500000,
            "state":"probe_bw","app_limited":false}"#;
        let s: WindowSample = serde_json::from_str(old).expect("an older window row must load");
        assert_eq!(s.bottleneck_bw_bps, 1_000_000);
        assert_eq!(
            s.bw_filter_window_ms, 0,
            "a row from before the field marks its horizon unknown, so the label \
             declines to name one"
        );
        assert_eq!(
            s.last_delivery_rate_bps, 0,
            "and the raw sample it also predates stays absent rather than reading \
             as a measured zero"
        );
        assert_eq!(
            (s.bytes_retransmitted, s.bytes_lost, s.inflight_hi_bytes),
            (0, 0, 0),
            "the loss columns postdate this row too; a run recorded before them \
             must load with them absent rather than fail to parse, which is the \
             only reason an archive is worth keeping"
        );
        assert_eq!(
            (
                s.loss_declarations,
                s.declared_by_packet_threshold,
                s.declared_by_time_threshold,
                s.declared_by_rto
            ),
            (0, 0, 0, 0),
            "and so does the declaration count and its split, which postdate even \
             the byte columns"
        );
    }

    /// The loss columns have to survive the round trip through the artifact, and
    /// they have to stay told apart.
    ///
    /// They are one measurement in two parts — copies emitted, holes charged —
    /// and the whole value of recording them is that a reader can subtract. A row
    /// that serialised both into one field, or swapped them, would still look
    /// like a plausible run: both are byte counts of the same magnitude.
    /// Distinct values in the fixture are what makes that visible.
    #[test]
    fn the_loss_columns_survive_a_round_trip_and_stay_distinct() {
        let row = phantom_leg_window_row();
        assert!(
            row.bytes_retransmitted > row.bytes_lost,
            "the fixture must describe a sender that spent more on copies than it \
             charged in holes — the shape a path that loses its repairs produces — \
             or it cannot tell a mixed-up column from a correct one"
        );

        let back: WindowSample = serde_json::from_str(
            &serde_json::to_string(&row).expect("a window row must serialize"),
        )
        .expect("and load back");

        assert_eq!(back.bytes_retransmitted, row.bytes_retransmitted);
        assert_eq!(back.bytes_lost, row.bytes_lost);
        assert_eq!(back.inflight_hi_bytes, row.inflight_hi_bytes);

        // The declaration count and its split ride the same trip, and the same
        // hazard applies with more surface: four small integers of similar size,
        // any pair of which could be swapped without the row looking wrong. The
        // fixture keeps all four apart and keeps the arms summing past the total,
        // which is the shape a real split has.
        assert_eq!(back.loss_declarations, row.loss_declarations);
        assert_eq!(back.repairs_attributed, row.repairs_attributed);
        assert_eq!(
            back.declared_by_packet_threshold,
            row.declared_by_packet_threshold
        );
        assert_eq!(
            back.declared_by_time_threshold,
            row.declared_by_time_threshold
        );
        assert_eq!(back.declared_by_rto, row.declared_by_rto);
        assert!(
            back.declared_by_packet_threshold != back.declared_by_time_threshold
                && back.declared_by_time_threshold != back.declared_by_rto
                && back.declared_by_packet_threshold != back.declared_by_rto,
            "the fixture must keep the three arms at distinct values, or a swap \
             between two of them survives this test"
        );
        assert!(
            [
                back.loss_declarations,
                back.repairs_attributed,
                back.declared_by_packet_threshold,
                back.declared_by_time_threshold,
                back.declared_by_rto,
            ]
            .iter()
            .all(|v| *v != 0),
            "no count in this fixture may be zero: a zero round-trips through a \
             dropped field, a skipped serialization and a mistyped name alike, so \
             a column pinned at zero is a column this test cannot see"
        );
        assert!(
            back.declared_by_packet_threshold
                + back.declared_by_time_threshold
                + back.declared_by_rto
                > back.repairs_attributed,
            "the arms exceed the copies by the joint orders; a fixture where they \
             merely summed to it could not tell a lost joint count from a correct \
             one"
        );
    }

    /// A window row shaped the way the Phantom legs record one.
    fn phantom_leg_window_row() -> WindowSample {
        WindowSample {
            leg: Leg::Udp,
            phase: "upload".to_string(),
            t_unix_ns: 1,
            elapsed_ms: 500,
            cwnd_bytes: 401_688,
            inflight_bytes: 120_000,
            bottleneck_bw_bps: 1_000_000,
            last_delivery_rate_bps: 980_000,
            bw_filter_window_ms: phantom_protocol::transport::bandwidth_estimator::BW_FILTER_WINDOW
                .as_millis() as u64,
            pacing_rate_bps: 1_000_000,
            min_rtt_us: 235_000,
            drain_outcomes: vec![41, 7, 3, 0, 11, 29],
            smoothed_rtt_us: 248_000,
            rtt_variation_us: 11_000,
            delivered_bytes: 500_000,
            state: "probe_bw".to_string(),
            app_limited: false,
            bytes_retransmitted: 34_680,
            bytes_lost: 11_560,
            loss_declarations: 10,
            repairs_attributed: 12,
            declared_by_packet_threshold: 7,
            declared_by_time_threshold: 4,
            declared_by_rto: 3,
            inflight_hi_bytes: 300_000,
        }
    }

    #[test]
    fn write_json_creates_parents() {
        let dir = std::env::temp_dir().join(format!("tb-wj-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("a").join("b").join("run.json");
        write_json(&path, &serde_json::json!({"ok": true})).expect("write");
        let back: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");
        assert_eq!(back["ok"], true);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
