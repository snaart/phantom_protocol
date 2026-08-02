//! The probe: profile definitions and the run orchestrator.
//!
//! Results are flushed to disk **after every scenario**, not at the end of the
//! run. A deep profile runs for hours unattended; if it is interrupted at hour
//! three, everything up to the current scenario must already be on disk. An
//! all-or-nothing writer would turn any interruption into a total loss.

pub mod conn;
pub mod scenarios;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;

use crate::probe::conn::Endpoints;
use crate::probe::scenarios::ScenarioOutput;
use crate::proto::{Msg, UPLOAD_CHUNK_SIZE};
use crate::report::{
    self, run_id_stamp, unix_nanos, utc_stamp, Leg, RunMeta, RunSummary, SampleSink,
    ScenarioSummary,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum Profile {
    /// ~10 minutes on a ~230 ms path. Enough to answer "is it alive and sane".
    Smoke,
    /// ~1 hour on a ~230 ms path. The full matrix at useful sample counts.
    Standard,
    /// ~4 hours on a ~230 ms path. Standard scaled up, plus a two-hour soak.
    Deep,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Standard => "standard",
            Self::Deep => "deep",
        }
    }
}

/// Every knob the matrix uses, resolved from the chosen profile.
#[derive(Debug, Clone)]
pub struct Params {
    pub clock_probes: usize,
    pub handshake_count: usize,
    pub rtt_sizes: Vec<usize>,
    pub rtt_per_size: usize,
    /// Sizes walked by `message_integrity`, bracketing the 1300 B split point.
    pub integrity_sizes: Vec<usize>,
    pub upload: Duration,
    pub download_bytes: u64,
    pub transfer_frame: u32,
    pub bidir_bytes: u64,
    /// Wall-clock ceiling on a single bulk transfer.
    ///
    /// The byte budgets above assume a link whose capacity is unknown before
    /// the run. Throughput measured over a bounded window is meaningful whether
    /// or not the full budget completed, so capping the window is strictly
    /// better than discovering mid-run that 256 MiB does not fit in the day.
    pub transfer_cap: Duration,
    /// Window for the raw TCP capacity probe.
    pub raw_throughput: Duration,
    /// Time spent at each offered rate in the raw UDP capacity probe.
    pub raw_rate_step: Duration,
    pub streams: usize,
    pub stream_frames: usize,
    pub stream_frame_bytes: usize,
    pub zero_rtt_rounds: usize,
    pub early_data_bytes: usize,
    pub migration_rounds: usize,
    pub migration_echoes: usize,
    pub rekey_threshold: u64,
    pub rekey_exchanges: usize,
    pub soak: Duration,
    pub soak_interval: Duration,
    pub concurrency: usize,
    pub concurrency_ops: usize,
}

impl Params {
    pub fn for_profile(p: Profile) -> Self {
        // Payload sizes bracket the measured 1420 B path MTU on purpose: 1024 B
        // fits one datagram, 4096 B forces PhantomUDP fragmentation, and 65536 B
        // is well past anything a single packet can carry.
        match p {
            Profile::Smoke => Self {
                clock_probes: 20,
                handshake_count: 10,
                rtt_sizes: vec![64, 1024, 8192],
                rtt_per_size: 20,
                integrity_sizes: vec![512, 1200, 1290, 1300, 1310, 2600, 8192],
                upload: Duration::from_secs(10),
                download_bytes: 8 * 1024 * 1024,
                transfer_frame: 1024,
                bidir_bytes: 4 * 1024 * 1024,
                transfer_cap: Duration::from_secs(60),
                raw_throughput: Duration::from_secs(15),
                raw_rate_step: Duration::from_secs(5),
                streams: 4,
                stream_frames: 10,
                stream_frame_bytes: 512,
                zero_rtt_rounds: 3,
                early_data_bytes: 256,
                migration_rounds: 2,
                migration_echoes: 20,
                rekey_threshold: 32,
                rekey_exchanges: 60,
                soak: Duration::from_secs(60),
                soak_interval: Duration::from_secs(5),
                concurrency: 8,
                concurrency_ops: 5,
            },
            Profile::Standard => Self {
                clock_probes: 40,
                handshake_count: 50,
                rtt_sizes: vec![16, 128, 512, 1024, 4096, 16384, 65536],
                rtt_per_size: 50,
                integrity_sizes: vec![
                    512, 1200, 1280, 1290, 1300, 1310, 1400, 2600, 4096, 8192, 65536,
                ],
                upload: Duration::from_secs(60),
                download_bytes: 64 * 1024 * 1024,
                transfer_frame: 1024,
                bidir_bytes: 32 * 1024 * 1024,
                transfer_cap: Duration::from_secs(180),
                raw_throughput: Duration::from_secs(30),
                raw_rate_step: Duration::from_secs(10),
                streams: 8,
                stream_frames: 30,
                stream_frame_bytes: 1024,
                zero_rtt_rounds: 20,
                early_data_bytes: 1024,
                migration_rounds: 10,
                migration_echoes: 40,
                rekey_threshold: 32,
                rekey_exchanges: 300,
                soak: Duration::from_secs(600),
                soak_interval: Duration::from_secs(10),
                concurrency: 32,
                concurrency_ops: 10,
            },
            Profile::Deep => Self {
                clock_probes: 60,
                handshake_count: 100,
                rtt_sizes: vec![16, 128, 512, 1024, 1400, 4096, 16384, 65536],
                rtt_per_size: 100,
                integrity_sizes: vec![
                    512, 1200, 1280, 1290, 1300, 1310, 1400, 2600, 4096, 8192, 65536, 262_144,
                ],
                upload: Duration::from_secs(180),
                download_bytes: 128 * 1024 * 1024,
                transfer_frame: 1024,
                bidir_bytes: 64 * 1024 * 1024,
                transfer_cap: Duration::from_secs(420),
                raw_throughput: Duration::from_secs(60),
                raw_rate_step: Duration::from_secs(15),
                streams: 16,
                stream_frames: 60,
                stream_frame_bytes: 1024,
                zero_rtt_rounds: 50,
                early_data_bytes: 4096,
                migration_rounds: 30,
                migration_echoes: 60,
                rekey_threshold: 32,
                rekey_exchanges: 1000,
                soak: Duration::from_secs(7200),
                soak_interval: Duration::from_secs(15),
                concurrency: 128,
                concurrency_ops: 20,
            },
        }
    }
}

pub struct ProbeConfig {
    pub endpoints: Endpoints,
    pub pin: Vec<u8>,
    pub profile: Profile,
    pub legs: Vec<Leg>,
    pub out_root: PathBuf,
    pub params: Params,
    pub upload_results: bool,
    /// When set, only these scenario names run. Everything else is skipped.
    pub only: Option<std::collections::HashSet<String>>,
}

impl ProbeConfig {
    fn wants(&self, scenario: &str) -> bool {
        self.only.as_ref().is_none_or(|s| s.contains(scenario))
    }

    /// The one leg that carries the long soak.
    ///
    /// Soaking every leg would triple the longest scenario in the matrix for
    /// almost no extra information — a `deep` run would spend six hours idling
    /// instead of two. PhantomUDP is the production transport and the only
    /// migration-capable one, so it gets the soak when it is in the run.
    fn soak_leg(&self) -> Option<Leg> {
        self.legs
            .iter()
            .copied()
            .find(|l| *l == Leg::Udp)
            .or_else(|| self.legs.iter().copied().find(|l| l.is_phantom()))
    }
}

/// Accumulates the run's outputs, flushing each scenario as it completes.
struct RunState {
    dir: PathBuf,
    meta: RunMeta,
    summaries: Vec<ScenarioSummary>,
    error_sink: SampleSink,
    total_errors: usize,
}

impl RunState {
    fn absorb(&mut self, leg: Leg, out: ScenarioOutput) -> Result<()> {
        let name = out.summary.scenario.clone();
        let path = self.dir.join("samples").join(leg.as_str()).join(&out.file);

        if !out.sink.is_empty() {
            out.sink.write_to(&path)?;
        }
        for e in &out.errors {
            self.error_sink.push(e);
            self.total_errors += 1;
        }
        // Rewrite the error log every scenario so an interrupted run still has
        // a complete failure record up to that point.
        if !self.error_sink.is_empty() {
            let ep = self.dir.join("errors.jsonl");
            let _ = std::fs::remove_file(&ep);
            self.error_sink.write_to(&ep)?;
        }

        let ok = out.summary.ok_count;
        let err = out.summary.error_count;
        let lat = out
            .summary
            .latency_ns
            .as_ref()
            .map(|s| format!(" p50={:.1}ms p99={:.1}ms", s.p50 / 1e6, s.p99 / 1e6))
            .unwrap_or_default();
        let tp = out
            .summary
            .throughput
            .as_ref()
            .map(|t| format!(" {:.2}Mbit/s", t.megabits_per_sec))
            .unwrap_or_default();
        println!("    [{leg}] {name}: ok={ok} err={err}{lat}{tp}");
        for n in &out.summary.notes {
            println!("        · {n}");
        }

        if let Some(c) = out.clock {
            self.meta.clock = Some(c);
        }
        self.summaries.push(out.summary);
        self.flush_summary()
    }

    fn flush_summary(&self) -> Result<()> {
        report::write_json(
            &self.dir.join("summary.json"),
            &RunSummary {
                run_id: self.meta.run_id.clone(),
                profile: self.meta.profile.clone(),
                scenarios: self.summaries.clone(),
            },
        )?;
        report::write_json(&self.dir.join("run.json"), &self.meta)?;
        Ok(())
    }
}

pub async fn run(cfg: ProbeConfig) -> Result<PathBuf> {
    let run_id = run_id_stamp();
    let dir = cfg.out_root.join(&run_id);
    std::fs::create_dir_all(&dir)?;

    let resolved = tokio::net::lookup_host(cfg.endpoints.addr_for(Leg::Tcp))
        .await
        .ok()
        .and_then(|mut it| it.next())
        .map(|a| a.to_string());

    let meta = RunMeta {
        run_id: run_id.clone(),
        profile: cfg.profile.as_str().to_string(),
        started_utc: utc_stamp(),
        started_unix_ns: unix_nanos(),
        finished_utc: None,
        finished_unix_ns: None,
        server_host: cfg.endpoints.host.clone(),
        server_resolved_addr: resolved,
        pin_hex: hex::encode(&cfg.pin),
        legs: cfg.legs.clone(),
        client: crate::sysinfo::host_info(Some(&cfg.endpoints.addr_for(Leg::Udp))),
        testbed_version: env!("CARGO_PKG_VERSION").to_string(),
        phantom_version: "0.2.2".to_string(),
        git_sha: git_sha(),
        clock: None,
        caveats: caveats(&cfg),
    };

    let mut st = RunState {
        dir: dir.clone(),
        meta,
        summaries: Vec::new(),
        error_sink: SampleSink::new(),
        total_errors: 0,
    };
    st.flush_summary()?;

    println!("run {run_id} — profile {}", cfg.profile.as_str());
    println!("results: {}", dir.display());
    println!();

    let ep = &cfg.endpoints;
    let pin = &cfg.pin;
    let p = &cfg.params;

    // Clock offset first: every one-way figure recorded later refers to it.
    if let Some(&first) = cfg
        .legs
        .iter()
        .find(|l| l.is_phantom())
        .filter(|_| cfg.wants("clock_sync"))
    {
        println!("  clock_sync via {first}");
        st.absorb(
            first,
            scenarios::clock_sync(ep, pin, first, p.clock_probes).await,
        )?;
    }

    for &leg in &cfg.legs {
        println!("\n  ── leg {leg} ──");

        if !leg.is_phantom() {
            if cfg.wants("rtt_sweep") {
                let out = match leg {
                    Leg::RawTcp => scenarios::raw_tcp_rtt(ep, &p.rtt_sizes, p.rtt_per_size).await,
                    Leg::RawUdp => scenarios::raw_udp_rtt(ep, &p.rtt_sizes, p.rtt_per_size).await,
                    _ => continue,
                };
                st.absorb(leg, out)?;
            }
            // The capacity denominator. Without it a protocol throughput number
            // cannot be attributed to the transport or to the link.
            if cfg.wants("throughput") {
                let out = match leg {
                    Leg::RawTcp => {
                        scenarios::raw_tcp_throughput(
                            ep,
                            p.raw_throughput,
                            p.transfer_frame as usize,
                        )
                        .await
                    }
                    Leg::RawUdp => scenarios::raw_udp_throughput(ep, p.raw_rate_step).await,
                    _ => continue,
                };
                st.absorb(leg, out)?;
            }
            continue;
        }

        // Ordered deliberately: cheap and diagnostic first, long-running last,
        // so an interrupted run still carries the scenarios that explain the
        // rest. `soak` is last on every leg for the same reason.
        if cfg.wants("handshake") {
            st.absorb(
                leg,
                scenarios::handshake(ep, pin, leg, p.handshake_count).await,
            )?;
        }
        if cfg.wants("rtt_sweep") {
            st.absorb(
                leg,
                scenarios::rtt_sweep(ep, pin, leg, &p.rtt_sizes, p.rtt_per_size).await,
            )?;
        }
        if cfg.wants("message_integrity") {
            st.absorb(
                leg,
                scenarios::message_integrity(ep, pin, leg, &p.integrity_sizes).await,
            )?;
        }
        if cfg.wants("upload") {
            st.absorb(
                leg,
                scenarios::upload(ep, pin, leg, p.upload, p.transfer_frame as usize).await,
            )?;
        }
        if cfg.wants("download") {
            st.absorb(
                leg,
                scenarios::download(
                    ep,
                    pin,
                    leg,
                    p.download_bytes,
                    p.transfer_frame,
                    p.transfer_cap,
                )
                .await,
            )?;
        }
        if cfg.wants("bidir") {
            st.absorb(
                leg,
                scenarios::bidir(
                    ep,
                    pin,
                    leg,
                    p.bidir_bytes,
                    p.transfer_frame,
                    p.transfer_cap,
                )
                .await,
            )?;
        }
        if cfg.wants("streams") {
            st.absorb(
                leg,
                scenarios::streams(
                    ep,
                    pin,
                    leg,
                    p.streams,
                    p.stream_frames,
                    p.stream_frame_bytes,
                )
                .await,
            )?;
        }
        if cfg.wants("zero_rtt") {
            st.absorb(
                leg,
                scenarios::zero_rtt(ep, pin, leg, p.zero_rtt_rounds, p.early_data_bytes).await,
            )?;
        }
        if cfg.wants("rekey") {
            st.absorb(
                leg,
                scenarios::rekey(ep, pin, leg, p.rekey_threshold, p.rekey_exchanges).await,
            )?;
        }
        if cfg.wants("migration") {
            st.absorb(
                leg,
                scenarios::migration(ep, pin, leg, p.migration_rounds, p.migration_echoes).await,
            )?;
        }
        if cfg.wants("concurrency") {
            st.absorb(
                leg,
                scenarios::concurrency(ep, pin, leg, p.concurrency, p.concurrency_ops).await,
            )?;
        }
        if cfg.wants("negative") {
            st.absorb(leg, scenarios::negative(ep, pin, leg).await)?;
        }
        if cfg.wants("liveness_soak") && cfg.soak_leg() == Some(leg) {
            st.absorb(
                leg,
                scenarios::liveness_soak(ep, pin, leg, p.soak, p.soak_interval).await,
            )?;
        }
    }

    st.meta.finished_utc = Some(utc_stamp());
    st.meta.finished_unix_ns = Some(unix_nanos());
    st.flush_summary()?;

    println!("\n  scenarios: {}", st.summaries.len());
    println!("  errors recorded: {}", st.total_errors);

    if cfg.upload_results {
        println!("\n  uploading the result bundle over the Phantom session itself…");
        match upload_bundle(&cfg, &dir).await {
            Ok((acked, total)) if acked == total => {
                println!("  uploaded and confirmed {acked}/{total} files")
            }
            Ok((acked, total)) => println!(
                "  only {acked}/{total} files were confirmed written — the local copy in {} is complete and is the system of record",
                dir.display()
            ),
            Err(e) => println!(
                "  upload failed ({e}) — the local copy in {} is complete and is the system of record",
                dir.display()
            ),
        }
    }

    println!("\ndone. results: {}", dir.display());
    Ok(dir)
}

/// Everything a reader must know before over-interpreting the numbers.
fn caveats(cfg: &ProbeConfig) -> Vec<String> {
    let mut v = vec![
        "RTT is the primary latency metric (single clock, exact). One-way figures depend on the clock_sync offset and carry its dispersion as an error bar.".to_string(),
        "Migration is a local UDP port rebind, not an interface change: it exercises the migration path and the server's path validation, but the external NAT mapping may not change and the client cannot observe whether it did.".to_string(),
        "Throughput is application-level goodput measured at the testbed protocol, so it excludes Phantom headers, AEAD tags, and any retransmission.".to_string(),
        "The raw TCP/UDP legs carry no Phantom at all; they are the control group, and protocol numbers are meaningful mainly as ratios against them.".to_string(),
    ];
    if let Some(l) = cfg.soak_leg() {
        v.push(format!(
            "The long soak ran only on the {l} leg; liveness and keepalive behaviour on the other legs is not covered by this run."
        ));
    }
    if cfg.profile == Profile::Smoke {
        v.push("Smoke profile: sample counts are small, so tail percentiles (p99, p999) are not statistically meaningful.".to_string());
    }
    if !cfg
        .legs
        .iter()
        .any(|l| *l == Leg::RawTcp || *l == Leg::RawUdp)
    {
        v.push("No raw baseline leg was selected, so protocol overhead cannot be separated from path cost in this run.".to_string());
    }
    v
}

fn git_sha() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Ship the result bundle to the daemon over a Phantom session.
///
/// Best-effort and deliberately last: the local copy is already complete and is
/// the system of record. If the transport is the thing that is broken, this is
/// exactly what fails, and losing it costs nothing.
async fn upload_bundle(cfg: &ProbeConfig, dir: &Path) -> Result<(usize, usize)> {
    let leg = cfg
        .legs
        .iter()
        .copied()
        .find(|l| *l == Leg::Udp)
        .or_else(|| cfg.legs.iter().copied().find(|l| l.is_phantom()))
        .ok_or_else(|| anyhow::anyhow!("no Phantom leg available to upload over"))?;

    let framed = conn::connect_framed(leg, &cfg.endpoints, &cfg.pin)
        .await
        .map_err(|e| anyhow::anyhow!("connect for upload: {e:?}"))?;

    let run_id = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let files = collect_files(dir);
    let total = files.len();
    let mut acked = 0usize;

    for file in files {
        let rel = file
            .strip_prefix(dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .to_string();
        let data = std::fs::read(&file)?;
        let name = format!("{run_id}/{rel}");

        conn::send_msg(
            &framed,
            Msg::UploadBegin {
                name: name.clone(),
                total_len: data.len() as u64,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("upload begin {name}: {e:?}"))?;

        for chunk in data.chunks(UPLOAD_CHUNK_SIZE) {
            conn::send_msg(
                &framed,
                Msg::UploadChunk {
                    data: chunk.to_vec(),
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("upload chunk {name}: {e:?}"))?;
        }

        conn::send_msg(
            &framed,
            Msg::UploadEnd {
                checksum: crate::proto::checksum(&data),
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("upload end {name}: {e:?}"))?;

        // Wait for the server to confirm the file is on its disk before moving
        // on. Without this the loop only measures how fast frames are accepted
        // into the session, and closing the session afterwards discards
        // everything still in flight — which is how a "45 files uploaded"
        // report came to mean two files actually written.
        match wait_upload_ack(&framed).await {
            Ok(true) => acked += 1,
            Ok(false) => println!("    · server rejected {name}"),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "no acknowledgement for {name} after {acked}/{total} files: {e:?}"
                ))
            }
        }
    }

    let _ = conn::send_msg(&framed, Msg::Bye).await;
    conn::close_session(framed.session()).await;
    Ok((acked, total))
}

/// Wait for the server's `UPLOAD_ACK`, ignoring anything else in flight.
async fn wait_upload_ack(
    framed: &crate::framing::Framed,
) -> Result<bool, phantom_protocol::CoreError> {
    // Generous: a bundle upload runs at whatever the link sustains, and the
    // acknowledgement sits behind the file's own bytes.
    let deadline = std::time::Instant::now() + conn::DRAIN_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(phantom_protocol::CoreError::Timeout);
        }
        let (msg, _) = tokio::time::timeout(remaining, framed.recv())
            .await
            .map_err(|_| phantom_protocol::CoreError::Timeout)??;
        if let Msg::UploadAck { ok, .. } = msg {
            return Ok(ok);
        }
    }
}

fn collect_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_is_internally_consistent() {
        for p in [Profile::Smoke, Profile::Standard, Profile::Deep] {
            let x = Params::for_profile(p);
            assert!(x.clock_probes > 0, "{:?}", p);
            assert!(x.handshake_count > 0);
            assert!(!x.rtt_sizes.is_empty());
            assert!(x.rtt_per_size > 0);
            assert!(
                x.integrity_sizes.iter().any(|&s| s < 1300)
                    && x.integrity_sizes.iter().any(|&s| s > 1300),
                "{p:?}: message_integrity must bracket the 1300 B split point"
            );
            assert!(x.upload > Duration::ZERO);
            assert!(x.download_bytes > 0);
            assert!(
                x.raw_throughput >= Duration::from_secs(10)
                    && x.raw_rate_step >= Duration::from_secs(5),
                "{p:?}: the capacity denominator needs a long enough window to mean anything"
            );
            assert!(
                x.transfer_cap >= Duration::from_secs(30),
                "{p:?}: a bulk-transfer window this short measures startup, not throughput"
            );
            assert!(
                x.transfer_frame >= 64,
                "frames must carry the header fields"
            );
            assert!(x.streams > 0 && x.stream_frames > 0);
            assert!(x.migration_rounds > 0 && x.migration_echoes >= 4);
            assert!(x.concurrency > 0 && x.concurrency_ops > 0);
            assert!(x.soak_interval > Duration::ZERO);
            assert!(
                x.soak >= x.soak_interval,
                "a soak shorter than its own probe interval collects nothing"
            );
            assert!(
                x.rekey_exchanges as u64 > x.rekey_threshold,
                "{:?}: too few exchanges to cross the rekey threshold even once",
                p
            );
        }
    }

    #[test]
    fn profiles_are_strictly_ordered_in_effort() {
        let s = Params::for_profile(Profile::Smoke);
        let m = Params::for_profile(Profile::Standard);
        let d = Params::for_profile(Profile::Deep);
        assert!(s.handshake_count < m.handshake_count);
        assert!(m.handshake_count < d.handshake_count);
        assert!(s.soak < m.soak && m.soak < d.soak);
        assert!(s.transfer_cap < m.transfer_cap && m.transfer_cap < d.transfer_cap);
        assert!(s.concurrency < m.concurrency && m.concurrency < d.concurrency);
        assert!(s.rtt_sizes.len() <= m.rtt_sizes.len());
        assert!(m.rtt_sizes.len() <= d.rtt_sizes.len());
    }

    /// The size sweep must bracket the measured 1420 B path MTU, or the
    /// fragmentation behaviour it exists to expose goes unmeasured.
    #[test]
    fn rtt_sizes_bracket_the_path_mtu() {
        for p in [Profile::Standard, Profile::Deep] {
            let x = Params::for_profile(p);
            assert!(
                x.rtt_sizes.iter().any(|&s| s < 1200),
                "{p:?} needs a size that fits one datagram"
            );
            assert!(
                x.rtt_sizes.iter().any(|&s| s > 1420),
                "{p:?} needs a size past the path MTU to force fragmentation"
            );
        }
    }

    /// The soak is the longest scenario in the matrix; running it per leg is
    /// what turns a two-hour soak into a six-hour one.
    #[test]
    fn the_soak_runs_on_exactly_one_leg_and_prefers_udp() {
        let cfg = demo_cfg(
            vec![Leg::Tcp, Leg::Udp, Leg::Mimic, Leg::RawUdp],
            Profile::Deep,
        );
        assert_eq!(cfg.soak_leg(), Some(Leg::Udp), "UDP wins when present");

        let no_udp = demo_cfg(vec![Leg::Mimic, Leg::Tcp, Leg::RawTcp], Profile::Deep);
        assert_eq!(
            no_udp.soak_leg(),
            Some(Leg::Mimic),
            "otherwise the first Phantom leg carries it"
        );

        let raw_only = demo_cfg(vec![Leg::RawTcp, Leg::RawUdp], Profile::Deep);
        assert_eq!(raw_only.soak_leg(), None, "raw controls hold no session");

        // And the artifact must say which leg it was.
        assert!(caveats(&cfg)
            .iter()
            .any(|c| c.contains("soak ran only on the udp leg")));
    }

    #[test]
    fn profile_names_are_stable() {
        assert_eq!(Profile::Smoke.as_str(), "smoke");
        assert_eq!(Profile::Standard.as_str(), "standard");
        assert_eq!(Profile::Deep.as_str(), "deep");
    }

    fn demo_cfg(legs: Vec<Leg>, profile: Profile) -> ProbeConfig {
        ProbeConfig {
            endpoints: Endpoints {
                host: "h".into(),
                tcp_port: 1,
                udp_port: 2,
                mimic_port: 3,
                raw_tcp_port: 4,
                raw_udp_port: 5,
                sni: "s".into(),
            },
            pin: vec![0; 64],
            profile,
            legs,
            out_root: PathBuf::from("/tmp"),
            params: Params::for_profile(profile),
            upload_results: false,
            only: None,
        }
    }

    #[test]
    fn caveats_flag_a_missing_control_group() {
        let c = caveats(&demo_cfg(vec![Leg::Udp], Profile::Standard));
        assert!(
            c.iter().any(|s| s.contains("No raw baseline leg")),
            "a run without controls must say so: {c:?}"
        );
        assert!(
            !caveats(&demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Standard))
                .iter()
                .any(|s| s.contains("No raw baseline leg"))
        );
    }

    #[test]
    fn smoke_runs_warn_about_meaningless_tails() {
        assert!(caveats(&demo_cfg(vec![Leg::Udp], Profile::Smoke))
            .iter()
            .any(|s| s.contains("not statistically meaningful")));
        assert!(!caveats(&demo_cfg(vec![Leg::Udp], Profile::Deep))
            .iter()
            .any(|s| s.contains("not statistically meaningful")));
    }

    #[test]
    fn caveats_always_state_the_migration_limitation() {
        for p in [Profile::Smoke, Profile::Standard, Profile::Deep] {
            assert!(
                caveats(&demo_cfg(vec![Leg::Udp], p))
                    .iter()
                    .any(|s| s.contains("not an interface change")),
                "the migration caveat must travel with every run"
            );
        }
    }

    /// `--only` must be an exact filter: naming one scenario must not silently
    /// enable a similarly-named neighbour, and omitting it must run everything.
    #[test]
    fn only_filter_is_exact_and_defaults_to_everything() {
        let all = demo_cfg(vec![Leg::Udp], Profile::Smoke);
        for s in [
            "clock_sync",
            "handshake",
            "rtt_sweep",
            "upload",
            "download",
            "bidir",
            "streams",
            "zero_rtt",
            "rekey",
            "migration",
            "concurrency",
            "negative",
            "liveness_soak",
        ] {
            assert!(all.wants(s), "no filter must run {s}");
        }

        let mut filtered = demo_cfg(vec![Leg::Udp], Profile::Smoke);
        filtered.only = Some(["rtt_sweep".to_string()].into_iter().collect());
        assert!(filtered.wants("rtt_sweep"));
        assert!(!filtered.wants("upload"));
        assert!(!filtered.wants("rtt"), "prefixes must not match");
        assert!(!filtered.wants("rtt_sweep_extra"));
    }

    #[test]
    fn collect_files_walks_nested_directories() {
        let dir = std::env::temp_dir().join(format!("tb-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("samples").join("udp")).expect("mkdir");
        std::fs::write(dir.join("run.json"), b"{}").expect("w");
        std::fs::write(dir.join("samples").join("udp").join("rtt.jsonl"), b"{}").expect("w");

        let files = collect_files(&dir);
        assert_eq!(files.len(), 2, "{files:?}");
        assert!(files.iter().all(|p| p.starts_with(&dir)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
