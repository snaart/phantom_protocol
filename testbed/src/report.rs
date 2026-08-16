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
/// windowed minimum. `inflight_bytes`, `bottleneck_bw_bps`, `pacing_rate_bps`,
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
    pub pacing_rate_bps: u64,
    pub min_rtt_us: u64,
    pub delivered_bytes: u64,
    /// BBR phase: startup / drain / probe_bw / probe_rtt. Loss does not appear
    /// here — it is answered by a bound on inflight, not by a phase change.
    pub state: String,
    /// True when the window had room and there was nothing to send — the
    /// application was the limit, not the transport.
    pub app_limited: bool,
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

/// One rung of a raw UDP capacity ladder, recorded from both ends.
///
/// The fields exist in pairs on purpose. A rung has an *offered* rate, a rate
/// the sender actually achieved on its own socket, and a rate the receiver
/// observed; collapsing those into one number is how a control comes to report
/// its own scheduler as the path's ceiling. So the sender's account travels
/// with the receiver's, and [`Self::sender_reached_offer`] states in a field —
/// not in prose — whether the rung is admissible as evidence at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownstreamSample {
    pub leg: Leg,
    /// `raw_udp_downstream` — server → client, no protocol in the way.
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
        let s = DownstreamSample {
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
        let unknown = DownstreamSample {
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
        let s: DownstreamSample = serde_json::from_str(old).expect("an older rung must load");
        assert_eq!(s.reordered_datagrams, 12);
        assert_eq!(
            s.reorder,
            crate::downlink::ReorderProfile::default(),
            "and its unmeasured profile must read as empty, not as zero reordering"
        );
        assert_eq!(s.reorder.horizon, 0, "a zero horizon marks it unmeasured");
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
