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
            Self::RawTcp => "raw_tcp",
            Self::RawUdp => "raw_udp",
        }
    }

    /// True for the legs that run a real Phantom session (as opposed to the
    /// raw-socket control group).
    pub fn is_phantom(self) -> bool {
        matches!(self, Self::Udp | Self::Tcp | Self::Mimic)
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
    pub git_sha: Option<String>,

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
/// `PhantomSession::send()` splits payloads above its internal 1300-byte
/// `TRANSPORT_MTU`, and the peer's `recv()` yields each piece separately. This
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
    /// BBR phase: startup / drain / probe_bw / probe_rtt / fast_recovery.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        for leg in [Leg::Udp, Leg::Tcp, Leg::Mimic, Leg::RawTcp, Leg::RawUdp] {
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
    }

    #[test]
    fn leg_properties() {
        assert!(Leg::Udp.supports_migration());
        assert!(!Leg::Tcp.supports_migration());
        assert!(!Leg::Mimic.supports_migration());
        assert!(Leg::Udp.is_phantom() && Leg::Tcp.is_phantom() && Leg::Mimic.is_phantom());
        assert!(!Leg::RawTcp.is_phantom() && !Leg::RawUdp.is_phantom());
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
