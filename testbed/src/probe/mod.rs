//! The probe: profile definitions and the run orchestrator.
//!
//! Results are flushed to disk **after every scenario**, not at the end of the
//! run. A deep profile runs for hours unattended; if it is interrupted at hour
//! three, everything up to the current scenario must already be on disk. An
//! all-or-nothing writer would turn any interruption into a total loss.

pub mod conn;
pub mod converge;
pub mod relay;
pub mod scenarios;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;

use crate::framing::MsgLink;
use crate::probe::conn::Endpoints;
use crate::probe::scenarios::ScenarioOutput;
use crate::proto::{Msg, UPLOAD_CHUNK_SIZE};
use crate::report::{
    self, run_id_stamp, unix_nanos, utc_stamp, BuildId, Leg, RunMeta, RunSummary, SampleSink,
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
    /// Handshakes deliberately damaged by `handshake_repair`, each losing one
    /// server reply flight.
    ///
    /// Small on every profile, and cheap: an attempt costs one handshake plus
    /// the client's first retransmit interval, so a couple of seconds. The
    /// reason to run more than one is not statistics but the path — an attempt
    /// whose flight the WAN partly lost before the relay saw it spends swallow
    /// budget on the repeat, and reports inconclusive rather than a result.
    pub repair_attempts: usize,
    pub rtt_sizes: Vec<usize>,
    pub rtt_per_size: usize,
    /// Sizes walked by `message_integrity`, bracketing the chunk split point
    /// (`phantom_protocol::transport::mtu::MAX_APP_CHUNK`).
    pub integrity_sizes: Vec<usize>,
    pub upload: Duration,
    pub download_bytes: u64,
    pub transfer_frame: u32,
    /// Frame sizes the `send_ceiling` sweep walks.
    ///
    /// Two of the three are what make the sweep able to answer anything, and
    /// which two is arithmetic rather than taste. The ARQ send buffer bounds a
    /// stream in **segments**, so its byte ceiling scales with the frame; the
    /// peer's flow-control window is a byte bound and does not. At a frame near
    /// one application chunk the two land within half a percent of each other
    /// and no recorded field separates them — which is exactly the default the
    /// `upload` scenario already runs at. So the sweep spends its rungs on the
    /// two ends where they *are* separated: one frame far below a chunk, where
    /// the buffer binds by a factor of four, and one whose wire form is an exact
    /// multiple of a chunk, where the peer's window binds by 13%. A rung at
    /// each end that lands on its own lower bound is what makes both bounds
    /// real, and the ambiguous middle then follows from arithmetic instead of
    /// from a measurement that cannot resolve it.
    pub ceiling_frames: Vec<u32>,
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
    /// Time spent at each offered rate in the raw UDP capacity probes.
    ///
    /// Shared by both directions so a downstream rung and its uplink twin are
    /// measured over the same window — comparing a five-second reading against
    /// a fifteen-second one would fold the difference into the answer.
    pub raw_rate_step: Duration,
    /// The offered-rate ladder both raw UDP controls walk, kbit/s.
    pub raw_rungs_kbps: Vec<u64>,
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
    /// Application messages the wire-encryption check sends while a capture is
    /// running.
    ///
    /// Every one of them becomes two needles searched against every captured
    /// frame, so this is the size of the negative search as well as the volume
    /// of established-session traffic the entropy distribution is drawn from.
    /// Small numbers make both weak; large ones buy little, because a leak
    /// would show in the first message.
    pub wire_messages: usize,
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
                repair_attempts: 2,
                rtt_sizes: vec![64, 1024, 8192],
                rtt_per_size: 20,
                integrity_sizes: vec![512, 1024, 1146, 1156, 1166, 2600, 8192],
                upload: Duration::from_secs(10),
                download_bytes: 8 * 1024 * 1024,
                transfer_frame: 1024,
                // The two ends only: the ambiguous middle is what `upload`
                // already runs, and a smoke run's whole budget is ten minutes.
                ceiling_frames: vec![256, scenarios::frame_filling_segments(2)],
                bidir_bytes: 4 * 1024 * 1024,
                transfer_cap: Duration::from_secs(60),
                raw_throughput: Duration::from_secs(15),
                raw_rate_step: Duration::from_secs(5),
                raw_rungs_kbps: crate::pacing::DEFAULT_RUNGS_KBPS.to_vec(),
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
                wire_messages: 32,
            },
            Profile::Standard => Self {
                clock_probes: 40,
                handshake_count: 50,
                repair_attempts: 4,
                rtt_sizes: vec![16, 128, 512, 1024, 4096, 16384, 65536],
                rtt_per_size: 50,
                integrity_sizes: vec![
                    512, 1024, 1140, 1146, 1156, 1166, 1200, 1400, 2600, 4096, 8192, 65536,
                ],
                upload: Duration::from_secs(60),
                download_bytes: 64 * 1024 * 1024,
                transfer_frame: 1024,
                // Plus the default frame, so the sweep carries the rung the rest
                // of the matrix is measured at rather than only its brackets.
                ceiling_frames: vec![256, 1024, scenarios::frame_filling_segments(2)],
                bidir_bytes: 32 * 1024 * 1024,
                transfer_cap: Duration::from_secs(180),
                raw_throughput: Duration::from_secs(30),
                raw_rate_step: Duration::from_secs(10),
                raw_rungs_kbps: crate::pacing::DEFAULT_RUNGS_KBPS.to_vec(),
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
                wire_messages: 96,
            },
            Profile::Deep => Self {
                clock_probes: 60,
                handshake_count: 100,
                repair_attempts: 8,
                rtt_sizes: vec![16, 128, 512, 1024, 1400, 4096, 16384, 65536],
                rtt_per_size: 100,
                integrity_sizes: vec![
                    512, 1024, 1140, 1146, 1156, 1166, 1200, 1400, 2600, 4096, 8192, 65536, 262_144,
                ],
                upload: Duration::from_secs(180),
                download_bytes: 128 * 1024 * 1024,
                transfer_frame: 1024,
                ceiling_frames: vec![
                    256,
                    1024,
                    scenarios::frame_filling_segments(2),
                    scenarios::frame_filling_segments(4),
                ],
                bidir_bytes: 64 * 1024 * 1024,
                transfer_cap: Duration::from_secs(420),
                raw_throughput: Duration::from_secs(60),
                raw_rate_step: Duration::from_secs(15),
                raw_rungs_kbps: crate::pacing::DEFAULT_RUNGS_KBPS.to_vec(),
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
                wire_messages: 192,
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
    /// Derive each bulk upload's window from the round trip this run measures,
    /// instead of running the profile's fixed number of seconds.
    ///
    /// See [`converge`]: convergence is counted in round trips, so a window
    /// fixed in seconds gives a long path *less* convergence than a short one,
    /// which is backwards. The measured round trip comes from `clock_sync`, and
    /// a run that will not reach it is refused up front rather than falling back
    /// silently — see [`ProbeConfig::validate`].
    pub upload_converge: bool,
    pub upload_results: bool,
    /// When set, only these scenario names run. Everything else is skipped.
    pub only: Option<std::collections::HashSet<String>>,
    /// Interface the `wire_capture` scenario captures on.
    ///
    /// `any` is the Linux pseudo-interface and is the useful default there; it
    /// does not exist on macOS or BSD, where a real interface name is required.
    /// Getting it wrong costs a recorded skip rather than a wrong answer.
    pub capture_iface: String,
}

impl ProbeConfig {
    fn wants(&self, scenario: &str) -> bool {
        self.only.as_ref().is_none_or(|s| s.contains(scenario))
    }

    /// Names in `--only` that no scenario answers to.
    ///
    /// The filter is exact, so a typo does not run a near-match — it runs
    /// nothing, and an hour later the operator has an empty directory and no
    /// idea why. Reported up front instead.
    fn unknown_filters(&self) -> Vec<String> {
        let Some(only) = &self.only else {
            return Vec::new();
        };
        let mut unknown: Vec<String> = only
            .iter()
            .filter(|s| {
                !PHANTOM_SCENARIOS.contains(&s.as_str()) && !RAW_SCENARIOS.contains(&s.as_str())
            })
            .cloned()
            .collect();
        unknown.sort();
        unknown
    }

    /// Refuse a run whose flags ask for something it cannot deliver.
    ///
    /// One case so far, and it is the shape worth refusing: `--upload-converge`
    /// sizes the upload window from the round trip `clock_sync` measures, so a
    /// run that filters `clock_sync` out, or that selects no leg it can run on,
    /// would fall back to the fixed window and record a fallback. That is a run
    /// spent measuring the thing the operator asked not to measure, and it is
    /// cheaper to say so before it starts than after.
    pub fn validate(&self) -> Result<()> {
        if self.upload_converge {
            anyhow::ensure!(
                self.wants("clock_sync"),
                "--upload-converge derives the upload window from the round trip clock_sync \
                 measures, and --only excludes clock_sync from this run"
            );
            anyhow::ensure!(
                self.legs.iter().any(|l| l.is_phantom()),
                "--upload-converge derives the upload window from the round trip clock_sync \
                 measures, and clock_sync runs over a Phantom leg — this run selects none"
            );
        }
        Ok(())
    }

    /// The one leg that carries the byte-ceiling sweep.
    ///
    /// One leg by design, like the soak, and for the same reason: each rung is a
    /// whole saturating transfer, so sweeping every leg multiplies the longest
    /// block in the matrix for an answer about `transport/stream.rs`, which is
    /// the same code underneath all of them. PhantomUDP gets it — it is the
    /// production transport and the leg the question was asked about.
    fn ceiling_leg(&self) -> Option<Leg> {
        self.legs
            .iter()
            .copied()
            .find(|l| *l == Leg::Udp)
            .or_else(|| self.legs.iter().copied().find(|l| l.is_phantom()))
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

/// Where a scenario's sidecar series lands, given the path of its own samples.
///
/// One derivation for every sidecar rather than one per call site. A transfer
/// leaves three files that an analysis joins by name alone — `upload.jsonl`,
/// `upload.window.jsonl`, `upload.receipt.jsonl` — and a second spelling of the
/// rule is a second place for the name to drift out of step with the reader
/// that opens it, which fails as a file that is simply never found.
fn sidecar_path(samples: &Path, kind: &str) -> PathBuf {
    samples.with_extension(format!("{kind}.jsonl"))
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
        if !out.window.is_empty() {
            out.window.write_to(&sidecar_path(&path, "window"))?;
        }
        if !out.receipt.is_empty() {
            out.receipt.write_to(&sidecar_path(&path, "receipt"))?;
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
        if let Some(b) = out.daemon_build {
            self.meta.daemon_build = Some(b);
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
    cfg.validate()?;
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
        build: BuildId::current(),
        // Filled from the daemon's STATS reply during clock_sync; see there.
        daemon_build: None,
        clock: None,
        suspensions: Vec::new(),
        caveats: caveats(&cfg),
    };

    // Started before the first scenario so the whole run is covered, including
    // the clock exchange the rest of the record is calibrated against.
    let suspend_watch = crate::suspend::SuspendWatch::new();
    let suspend_task = suspend_watch.spawn();

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
    let unknown = cfg.unknown_filters();
    if !unknown.is_empty() {
        println!(
            "  warning: --only names no scenario answers to: {} (nothing will run for those)",
            unknown.join(", ")
        );
    }
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

    // Every bulk upload in this run gets the same window, resolved once and
    // here — after `clock_sync`, which is what measures the round trip it is
    // derived from, and before the first leg, so that the legs are comparable
    // with each other. The note travels into the run's caveats as well as into
    // each upload's own summary, because it is the difference between a rate
    // and a convergence time and that has to be beside the number wherever the
    // number is read.
    let upload_window = converge::UploadWindow::resolve(
        cfg.upload_converge,
        p.upload,
        st.meta
            .clock
            .as_ref()
            .map(|c| Duration::from_nanos(c.min_rtt_ns)),
    );
    println!("\n  {}", upload_window.note());
    st.meta.caveats.push(upload_window.note());
    st.flush_summary()?;

    for &leg in &cfg.legs {
        println!("\n  ── leg {leg} ──");

        if leg.is_reference() {
            run_reference_leg(&cfg, &mut st, leg, &upload_window).await?;
            continue;
        }

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
                    Leg::RawUdp => {
                        scenarios::raw_udp_throughput(ep, &p.raw_rungs_kbps, p.raw_rate_step).await
                    }
                    _ => continue,
                };
                st.absorb(leg, out)?;
            }
            // The same ladder, one way, server → client. Both echoes above are
            // round trips and so bound neither direction on its own; this is
            // the only figure a `download` can honestly be divided by.
            if leg == Leg::RawUdp && cfg.wants("downstream") {
                st.absorb(
                    leg,
                    scenarios::raw_udp_downstream(ep, &p.raw_rungs_kbps, p.raw_rate_step).await,
                )?;
            }
            // And its mirror, client → server, which is what an `upload` is
            // divided by. Run immediately after the downstream ladder and over
            // the same window on the same rungs, because the two numbers are
            // read side by side and a path's capacity moves between minutes.
            if leg == Leg::RawUdp && cfg.wants("upstream") {
                st.absorb(
                    leg,
                    scenarios::raw_udp_upstream(ep, &p.raw_rungs_kbps, p.raw_rate_step).await,
                )?;
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
        // Right after the undamaged handshake numbers, because it is read
        // against them: the same exchange with one reply flight deliberately
        // missing. Cheap — one handshake plus the client's first retransmit
        // interval per attempt.
        if cfg.wants("handshake_repair") {
            st.absorb(
                leg,
                scenarios::handshake_repair(ep, pin, leg, p.repair_attempts).await,
            )?;
        }
        // Early, and on its own fresh session: the capture has to be running
        // before the handshake it needs for a positive control.
        if cfg.wants("wire_capture") {
            st.absorb(
                leg,
                scenarios::wire_capture(ep, pin, leg, &cfg.capture_iface, p.wire_messages, &dir)
                    .await,
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
                scenarios::upload(ep, pin, leg, &upload_window, p.transfer_frame as usize).await,
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
        // Last of the bulk block, and on one leg only: each rung is a whole
        // saturating transfer of its own.
        if cfg.wants("send_ceiling") && cfg.ceiling_leg() == Some(leg) {
            st.absorb(
                leg,
                scenarios::send_ceiling(ep, pin, leg, &p.ceiling_frames, &upload_window).await,
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
    // Before anything else is written or printed: whether this process was
    // running for the run it just recorded. A suspension turns Timeouts and
    // fallen rates into artifacts of the host rather than of the path, and the
    // reader has to be told that ahead of the numbers, not after them.
    suspend_task.abort();
    st.meta.suspensions = suspend_watch.take();
    let run_span = Duration::from_nanos(
        st.meta
            .finished_unix_ns
            .unwrap_or(st.meta.started_unix_ns)
            .saturating_sub(st.meta.started_unix_ns),
    );
    let suspend_verdict = crate::suspend::verdict(&st.meta.suspensions, run_span);
    if let Some(v) = suspend_verdict.clone() {
        st.meta.caveats.push(v);
    }
    st.flush_summary()?;

    if let Some(v) = suspend_verdict {
        println!("\n  VERDICT host suspended: {v}");
    }

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

/// Scenario names the raw controls answer to. They carry no protocol, so they
/// run only the probes that describe the path itself.
///
/// `throughput` is a round trip; `downstream` and `upstream` are one way each.
/// All three are here because they answer different questions: the first bounds
/// what the path can carry at all, and the other two bound the two directions
/// every `download` and `upload` figure in the run is measured in. A round trip
/// bounds neither on its own, which is why one one-way control is not enough
/// either.
const RAW_SCENARIOS: &[&str] = &["rtt_sweep", "throughput", "downstream", "upstream"];

/// Every scenario the matrix runs against the protocol under test.
///
/// The reference leg must account for each of these — either by running it
/// ([`QUIC_COVERED`]) or by saying why it does not ([`QUIC_SKIPPED`]). A test
/// pins that, so a scenario added later cannot silently go unaccounted-for on
/// the leg the whole comparison rests on.
const PHANTOM_SCENARIOS: &[&str] = &[
    "clock_sync",
    "handshake",
    "handshake_repair",
    "wire_capture",
    "rtt_sweep",
    "message_integrity",
    "upload",
    "download",
    "bidir",
    "send_ceiling",
    "streams",
    "zero_rtt",
    "rekey",
    "migration",
    "concurrency",
    "negative",
    "liveness_soak",
];

/// Scenarios the QUIC reference leg runs.
///
/// The five the comparison turns on — handshake, latency, and the three bulk
/// transfers — plus `concurrency`, which measures connection setup under load
/// and costs nothing extra because both legs reach it through the same code.
const QUIC_COVERED: &[&str] = &[
    "handshake",
    "rtt_sweep",
    "upload",
    "download",
    "bidir",
    "concurrency",
];

/// Scenarios the QUIC reference leg does not run, and why.
///
/// Each is recorded as a skipped entry in `summary.json` rather than quietly
/// omitted: a reader comparing the two legs must be able to see that the gap in
/// coverage was a decision, and read the reason without leaving the artifact.
const QUIC_SKIPPED: &[(&str, &str)] = &[
    (
        "clock_sync",
        "the run's clock offset is estimated once, on a Phantom leg; a second estimate over a different transport would not be a second measurement of anything",
    ),
    (
        "handshake_repair",
        "it damages a PhantomUDP handshake on purpose — one datagram flight of the server's reply is dropped before it reaches the client — and then asserts that the listener's retained-flight repeat carries the connect anyway. quinn's handshake is neither shaped like that nor repaired like that: its Initial and Handshake packets are individually acknowledged and retransmitted by the QUIC loss recovery in every implementation, so the failure this exists to catch cannot occur there and the counters it reads have no counterpart",
    ),
    (
        "message_integrity",
        "this measures a property of PhantomSession::send() — that it splits payloads above its internal chunk size and delivers the pieces separately. QUIC streams have no message boundaries at all, by specification, so the same probe would report an expected non-property as though it were a defect",
    ),
    (
        "send_ceiling",
        "the sweep exists to tell two of this protocol's own byte ceilings apart — the ARQ send buffer, which is bounded in segments and so moves with the frame size, and the peer's advertised flow-control window, which is bounded in bytes and does not. quinn has neither bound in that shape and reports no bytes in flight at all, so its rungs would carry no reading",
    ),
    (
        "streams",
        "the reference leg deliberately uses a single bidirectional stream so that the byte-pipe comparison is like-for-like; measuring QUIC's multiplexing would need a different server shape and would not be comparing anything the Phantom legs do here",
    ),
    (
        "zero_rtt",
        "quinn's 0-RTT needs a session-ticket cache carried across connections and a separate accept path on the daemon; not wired, so the comparison is not offered rather than offered wrongly",
    ),
    (
        "rekey",
        "key update is driven through PhantomSession::set_rekey_threshold, which has no counterpart in the quinn API surface used here",
    ),
    (
        "migration",
        "connection migration is exercised through PhantomSession::migrate(); quinn's is not driven by this harness",
    ),
    (
        "negative",
        "the negative cases assert Phantom's typed errors on a wrong pin, a closed port, and a junk flood; asserting quinn's behaviour would be testing quinn, which is not what this leg is for",
    ),
    (
        "liveness_soak",
        "the soak runs on exactly one leg by design — see the run's caveats for which",
    ),
    (
        "wire_capture",
        "the check turns on a positive control that is specific to the protocol under test: the build's PROTOCOL_VARIANT tag, which rides in the clear in a signed-but-unencrypted ClientHello. quinn's handshake has no field this probe generates, so the control would have to be a string out of rustls, and finding it would be evidence about rustls rather than about anything measured here",
    ),
];

/// Drive the scenarios the reference leg does cover, and record the rest as
/// skipped.
async fn run_reference_leg(
    cfg: &ProbeConfig,
    st: &mut RunState,
    leg: Leg,
    upload_window: &converge::UploadWindow,
) -> Result<()> {
    /// Both the operator's `--only` filter and the leg's own coverage list have
    /// to agree. Routing through [`QUIC_COVERED`] rather than hard-coding the
    /// names here is what makes that list load-bearing instead of decorative.
    fn runs(cfg: &ProbeConfig, scenario: &str) -> bool {
        cfg.wants(scenario) && QUIC_COVERED.contains(&scenario)
    }

    let ep = &cfg.endpoints;
    let pin = &cfg.pin;
    let p = &cfg.params;

    if ep.quic_cert.is_none() {
        st.absorb(
            leg,
            scenarios::skipped(
                leg,
                "handshake",
                "no certificate was pinned for this leg (pass --quic-cert-file or --quic-cert-hex); \
                 connecting without verification would measure something other than a handshake",
            ),
        )?;
        return Ok(());
    }

    if runs(cfg, "handshake") {
        st.absorb(
            leg,
            scenarios::handshake(ep, pin, leg, p.handshake_count).await,
        )?;
    }
    if runs(cfg, "rtt_sweep") {
        st.absorb(
            leg,
            scenarios::rtt_sweep(ep, pin, leg, &p.rtt_sizes, p.rtt_per_size).await,
        )?;
    }
    if runs(cfg, "upload") {
        st.absorb(
            leg,
            scenarios::upload(ep, pin, leg, upload_window, p.transfer_frame as usize).await,
        )?;
    }
    if runs(cfg, "download") {
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
    if runs(cfg, "bidir") {
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
    if runs(cfg, "concurrency") {
        st.absorb(
            leg,
            scenarios::concurrency(ep, pin, leg, p.concurrency, p.concurrency_ops).await,
        )?;
    }

    for (scenario, why) in QUIC_SKIPPED {
        if cfg.wants(scenario) {
            st.absorb(leg, scenarios::skipped(leg, scenario, why))?;
        }
    }
    Ok(())
}

/// Everything a reader must know before over-interpreting the numbers.
fn caveats(cfg: &ProbeConfig) -> Vec<String> {
    let mut v = vec![
        "RTT is the primary latency metric (single clock, exact). One-way figures depend on the clock_sync offset and carry its dispersion as an error bar.".to_string(),
        "Migration is a local UDP port rebind, not an interface change: it exercises the migration path and the server's path validation, but the external NAT mapping may not change and the client cannot observe whether it did.".to_string(),
        "Throughput is application-level goodput measured at the testbed protocol, so it excludes Phantom headers, AEAD tags, and any retransmission.".to_string(),
        "The raw TCP/UDP legs carry no Phantom at all, and the raw UDP ladders are the denominator every protocol throughput number is a ratio against.".to_string(),
        "The raw TCP and raw UDP throughput controls are round trips: every byte they count crossed the path twice, so neither bounds a single direction. The one-way controls are the raw_udp downstream and upstream ladders, which cover server -> client and client -> server respectively; each is the denominator for one direction and neither speaks for the other.".to_string(),
    ];
    if cfg.legs.contains(&Leg::RawTcp) {
        v.push("\"Raw\" on the TCP leg means no Phantom, not no protocol, and for TCP those differ. A UDP socket adds nothing to the path, which is what makes the datagram ladders denominators; a TCP socket adds congestion control, reliability and flow control, which are the mechanisms under test. The raw TCP echo's throughput is therefore what a kernel TCP achieves here - a yardstick of the same kind as the QUIC leg, not a floor beneath a TCP-substrate leg. A one-way tcp or mimic figure above it is expected, because that one crossed the path once and this one twice. Its latency sweep is a different matter and remains the path's own round-trip floor.".to_string());
    }
    if cfg.legs.iter().any(|l| matches!(l, Leg::Tcp | Leg::Mimic)) {
        v.push("No one-way TCP control exists in this harness. One would need a source port and a sink port on the daemon counting arrivals at the receiving end, one connection per direction so the measured direction's acknowledgements are not queued behind the other's data, and socket buffers verified by grant at both ends - and it would still be a reference rather than a control, for the reason above. Until then a tcp or mimic figure is normalised by the raw UDP ladder for its direction, which measures the path both substrates ride.".to_string());
    }
    if !cfg.wants("downstream") || !cfg.legs.contains(&Leg::RawUdp) {
        v.push("No one-way downstream control ran, so this run cannot say whether a low download figure is the transport or the server's uplink.".to_string());
    }
    if !cfg.wants("upstream") || !cfg.legs.contains(&Leg::RawUdp) {
        v.push("No one-way upstream control ran, so this run cannot say whether a low upload figure is the transport or the client's uplink, and its upload numbers have nothing to be normalised against.".to_string());
    }
    if cfg.legs.iter().any(|l| l.is_reference()) {
        v.push(
            "The quic leg is a reference implementation, not the protocol under test and not a control: quinn over the same path, driving the same testbed application protocol over one bidirectional stream.".to_string(),
        );
        v.push(
            "quinn is TLS 1.3 with classical cryptography, while the protocol under test does a hybrid post-quantum key exchange, so handshake latencies are not comparable like-for-like and the difference is expected. Throughput and loss behaviour are comparable.".to_string(),
        );
        v.push(
            "quinn's default congestion controller is Cubic (loss-based) and is deliberately left at its default; the protocol under test uses a BBR-style estimator. The two congestion-window series are not the same statistic — compare outcomes, not the shape of the curve.".to_string(),
        );
        v.push(
            "The quic leg's flow-control windows are raised to 8 MiB so that flow control is not the binding constraint instead of the path; quinn's own default stream window (1.25 MB) would cap a 250 ms path near 40 Mbit/s. That is not the 1 MiB the raw TCP control asks for, deliberately: the control also sends, and at 8 MiB it filled its own send buffer and reported its queue as the link.".to_string(),
        );
        v.push(
            "In the quic leg's window samples only cwnd_bytes and min_rtt_us carry values, and min_rtt_us holds quinn's smoothed RTT rather than a windowed minimum; quinn exposes no bytes-in-flight, bandwidth estimate, pacing rate, delivered total or app-limited flag, so those fields are zero rather than approximated. Its loss counters appear in the scenario notes.".to_string(),
        );
        v.push(
            "The quic leg pins the daemon's self-signed certificate as its only trust anchor and performs ordinary rustls path and name validation against it; certificate verification is not disabled anywhere.".to_string(),
        );
    }
    if cfg.wants("wire_capture") && cfg.legs.iter().any(|l| l.is_phantom()) {
        v.push(
            "The wire_capture scenario needs elevated capture rights on the machine running the probe. Where it could not get them it records a skip with the reason instead of a result, so a run carrying that skip has not examined the wire at all — check its verdict before quoting anything about encryption from this run.".to_string(),
        );
        v.push(
            "No capture can show that every post-handshake packet carries the ENCRYPTED flag: header protection masks the whole packet header on the wire. The wire_capture record answers that from the source and says so; nothing measured in this run is evidence about it.".to_string(),
        );
    }
    if cfg.wants("handshake_repair") && cfg.legs.contains(&Leg::Udp) {
        v.push(
            "The handshake_repair scenario manufactures its own loss: a relay on this machine drops one datagram flight of the server's reply before it reaches the client. Every datagram still crosses the real path in both directions and only the delivery decision is local, so what it reports is a real handshake with a real flight missing rather than a simulation. An attempt that lost nothing is recorded as inconclusive rather than as a pass, and its numbers are not evidence about the repair.".to_string(),
        );
    }
    if cfg.legs.contains(&Leg::RawUdp) && (cfg.wants("downstream") || cfg.wants("upstream")) {
        v.push(
            "Reordering is measured by the raw controls only, and a reordering figure from one run is not a property of the path: two adjacent runs over this same route gave 13.4% reordering at 0.12% loss and 0% reordering at 7.69% loss. Any tolerance sized on a single run is sized on that run's weather.".to_string(),
        );
    }
    if cfg.wants("send_ceiling") {
        if let Some(l) = cfg.ceiling_leg() {
            v.push(format!(
                "The byte-ceiling sweep ran only on the {l} leg. The two bounds it separates — the ARQ send buffer and the peer's flow-control window — live in code every Phantom leg shares, but the byte pipe underneath differs, so this run says nothing about where a saturated sender sits on the other legs."
            ));
        }
    }
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
        // Scale the wait to the file: the acknowledgement sits behind the
        // file's own bytes, and a deep run's largest samples are far bigger
        // than a smoke run's. 8 KB/s is a deliberately pessimistic floor.
        let budget = conn::DRAIN_TIMEOUT.max(Duration::from_secs(
            (data.len() as u64 / 8_000).saturating_add(10),
        ));
        match wait_upload_ack(&framed, budget).await {
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
    budget: Duration,
) -> Result<bool, phantom_protocol::CoreError> {
    let deadline = std::time::Instant::now() + budget;
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
    // The size at which `PhantomSession::send()` stops preserving message
    // boundaries, taken from the library rather than restated — so the sizes the
    // integrity probe walks keep bracketing the real split point if the path-MTU
    // budget ever moves.
    use phantom_protocol::transport::mtu::MAX_APP_CHUNK;

    /// A sidecar an analysis cannot find is a sidecar that was never written.
    /// The three files a transfer leaves are joined by name and by nothing else,
    /// so the naming rule is pinned here rather than restated per call site.
    #[test]
    fn a_scenarios_sidecars_sit_beside_its_samples_under_predictable_names() {
        let samples = PathBuf::from("results/run/samples/udp/upload.jsonl");

        assert_eq!(
            sidecar_path(&samples, "window"),
            PathBuf::from("results/run/samples/udp/upload.window.jsonl")
        );
        assert_eq!(
            sidecar_path(&samples, "receipt"),
            PathBuf::from("results/run/samples/udp/upload.receipt.jsonl")
        );
        // Same directory as the samples, and one file per kind: a sidecar that
        // landed elsewhere, or that two kinds shared, would be read as the other.
        assert_eq!(sidecar_path(&samples, "receipt").parent(), samples.parent());
        assert_ne!(
            sidecar_path(&samples, "receipt"),
            sidecar_path(&samples, "window")
        );
    }

    #[test]
    fn every_profile_is_internally_consistent() {
        for p in [Profile::Smoke, Profile::Standard, Profile::Deep] {
            let x = Params::for_profile(p);
            assert!(x.clock_probes > 0, "{:?}", p);
            assert!(x.handshake_count > 0);
            assert!(!x.rtt_sizes.is_empty());
            assert!(x.rtt_per_size > 0);
            assert!(
                x.integrity_sizes.iter().any(|&s| s < MAX_APP_CHUNK)
                    && x.integrity_sizes.iter().any(|&s| s > MAX_APP_CHUNK),
                "{p:?}: message_integrity must bracket the {MAX_APP_CHUNK} B split point"
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
            // The wire check draws its entropy distribution from these
            // messages, and a distribution over a handful of samples is not a
            // distribution.
            assert!(
                x.wire_messages >= 16,
                "{p:?}: {} messages is too few to say anything about the payload distribution",
                x.wire_messages
            );
        }
    }

    /// The wire check is only as good as the traffic it searches, so the
    /// heavier profiles must search more of it — and the caveat that a skipped
    /// check examined nothing has to travel with every run that asks for one.
    #[test]
    fn the_wire_check_scales_with_the_profile_and_states_what_a_skip_means() {
        let s = Params::for_profile(Profile::Smoke);
        let m = Params::for_profile(Profile::Standard);
        let d = Params::for_profile(Profile::Deep);
        assert!(s.wire_messages < m.wire_messages && m.wire_messages < d.wire_messages);

        let c = caveats(&demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Standard)).join("\n");
        assert!(c.contains("elevated capture rights"), "{c}");
        assert!(
            c.contains("has not examined the wire at all"),
            "a skipped security check must not read as a passed one: {c}"
        );
        assert!(
            c.contains("header protection masks the whole packet header"),
            "the one question a capture cannot answer must be named: {c}"
        );

        // A run with no Phantom leg never reaches the scenario, so it must not
        // carry caveats about a check it did not attempt.
        let raw_only =
            caveats(&demo_cfg(vec![Leg::RawTcp, Leg::RawUdp], Profile::Smoke)).join("\n");
        assert!(!raw_only.contains("wire_capture"), "{raw_only}");
    }

    /// The raw TCP echo has come in under the TCP-substrate legs it was being
    /// read as bounding, twice, and both times the reading that followed was
    /// "the control is broken". It is not: a one-way figure is not bounded by a
    /// two-way one, and a TCP socket is not a protocol-free substrate. A run
    /// that carries the echo has to carry both sentences, or the inversion will
    /// be reinterpreted from scratch every campaign.
    #[test]
    fn the_raw_tcp_echo_is_not_offered_as_a_one_way_denominator() {
        let c = caveats(&demo_cfg(
            vec![Leg::Tcp, Leg::Mimic, Leg::RawTcp, Leg::RawUdp],
            Profile::Standard,
        ))
        .join("\n");
        assert!(
            c.contains("no Phantom, not no protocol"),
            "the word \"raw\" has to be qualified where it is misleading: {c}"
        );
        assert!(c.contains("not a floor beneath a TCP-substrate leg"), "{c}");
        assert!(
            c.contains("above it is expected"),
            "the inversion must be pre-empted rather than left to read as a fault: {c}"
        );
        assert!(
            c.contains("No one-way TCP control exists in this harness"),
            "a missing control is a fact about the run: {c}"
        );
        assert!(
            c.contains("normalised by the raw UDP ladder for its direction"),
            "saying what is missing is only half of it; the denominator that does exist has to be named: {c}"
        );

        // A run that drove neither the echo nor a TCP-substrate leg has neither
        // reading to pre-empt, and a caveat about a leg that did not run is
        // noise a reader has to discount.
        let udp_only = caveats(&demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Smoke)).join("\n");
        assert!(
            !udp_only.contains("no Phantom, not no protocol"),
            "{udp_only}"
        );
        assert!(
            !udp_only.contains("No one-way TCP control exists"),
            "{udp_only}"
        );
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

    /// The damaged-handshake scenario has to run everywhere and stay cheap.
    ///
    /// An attempt costs one handshake plus the client's first retransmit interval —
    /// roughly two seconds on a long path — so a profile asking for dozens would
    /// quietly turn a ten-minute smoke run into somebody else's soak. The ordering
    /// is the same rule every other knob follows, and the manufactured loss has to
    /// travel in the caveats or a reader will take the connect times for ordinary
    /// ones.
    #[test]
    fn the_repair_scenario_runs_on_every_profile_and_says_it_makes_its_own_loss() {
        let (s, m, d) = (
            Params::for_profile(Profile::Smoke),
            Params::for_profile(Profile::Standard),
            Params::for_profile(Profile::Deep),
        );
        for (p, x) in [
            (Profile::Smoke, &s),
            (Profile::Standard, &m),
            (Profile::Deep, &d),
        ] {
            assert!(
                x.repair_attempts > 0,
                "{p:?}: a scenario that runs zero attempts reports nothing and looks green"
            );
        }
        assert!(s.repair_attempts < m.repair_attempts);
        assert!(m.repair_attempts < d.repair_attempts);
        assert!(
            s.repair_attempts <= 4,
            "the smoke profile's whole budget is ten minutes"
        );

        let c = caveats(&demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Smoke)).join("\n");
        assert!(c.contains("manufactures its own loss"), "{c}");
        assert!(
            c.contains("inconclusive rather than as a pass"),
            "an attempt that damaged nothing must not read as a result: {c}"
        );

        // A run with no PhantomUDP leg never reaches the scenario, so it must not
        // carry a caveat about loss it did not manufacture.
        let no_udp = caveats(&demo_cfg(vec![Leg::Tcp, Leg::RawTcp], Profile::Smoke)).join("\n");
        assert!(!no_udp.contains("manufactures its own loss"), "{no_udp}");
    }

    /// A derived upload window is measured against the round trip `clock_sync`
    /// produces. A run that cannot reach that scenario would fall back to the
    /// fixed window and spend its wall clock measuring the thing the operator
    /// asked not to measure, so it is refused before it starts.
    #[test]
    fn a_derived_upload_window_needs_the_scenario_that_measures_the_path() {
        let mut cfg = demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Smoke);
        cfg.upload_converge = true;
        assert!(cfg.validate().is_ok(), "clock_sync runs by default");

        cfg.only = Some(["upload".to_string()].into_iter().collect());
        let e = cfg
            .validate()
            .expect_err("filtering clock_sync out must be refused");
        assert!(format!("{e}").contains("clock_sync"), "{e}");

        // And a run with no Phantom leg has no session to measure it over.
        let mut raw_only = demo_cfg(vec![Leg::RawUdp], Profile::Smoke);
        raw_only.upload_converge = true;
        assert!(raw_only.validate().is_err());

        // None of this constrains a run that did not ask for it.
        let mut plain = demo_cfg(vec![Leg::RawUdp], Profile::Smoke);
        plain.only = Some(["upload".to_string()].into_iter().collect());
        assert!(plain.validate().is_ok());
    }

    /// The sweep's rungs are what separate the two byte ceilings, and they only
    /// do that at the two ends: below one application chunk the send buffer is
    /// the lower bound, at a whole multiple of one the peer's window is. A
    /// profile whose ladder sat entirely on one side would run for the same wall
    /// clock and settle nothing.
    #[test]
    fn every_profiles_ceiling_ladder_brackets_the_crossover() {
        let peer = phantom_protocol::transport::stream::MAX_SEND_WINDOW as u64;
        let segments = 1024u64; // scenarios::SEND_BUFFER_SEGMENTS, restated by the test
        for p in [Profile::Smoke, Profile::Standard, Profile::Deep] {
            let x = Params::for_profile(p);
            assert!(
                x.ceiling_frames.len() >= 2,
                "{p:?}: one rung separates nothing"
            );
            let mut buffer_binds = false;
            let mut window_binds = false;
            for &f in &x.ceiling_frames {
                assert!(f >= 64, "{p:?}: frames must carry the header fields");
                let wire = scenarios::sink_wire_bytes(f as usize) as u64;
                let per_frame =
                    wire.div_ceil(phantom_protocol::transport::mtu::MAX_APP_CHUNK as u64);
                let arq = (segments / per_frame.max(1)) * wire;
                buffer_binds |= arq * 2 < peer;
                window_binds |= arq > peer;
            }
            assert!(
                buffer_binds,
                "{p:?}: no rung where the send buffer is clearly the lower bound"
            );
            assert!(
                window_binds,
                "{p:?}: no rung where the peer's window is the lower bound"
            );
        }
    }

    /// Each rung is a whole saturating transfer, so the sweep runs on one leg —
    /// the production transport when it is in the run — and the artifact says
    /// which, because the other legs are then uncovered.
    #[test]
    fn the_ceiling_sweep_runs_on_one_leg_and_says_which() {
        let cfg = demo_cfg(vec![Leg::Tcp, Leg::Udp, Leg::RawUdp], Profile::Smoke);
        assert_eq!(cfg.ceiling_leg(), Some(Leg::Udp));
        assert_eq!(
            demo_cfg(vec![Leg::Mimic, Leg::Tcp], Profile::Smoke).ceiling_leg(),
            Some(Leg::Mimic),
            "otherwise the first Phantom leg carries it"
        );
        assert_eq!(
            demo_cfg(vec![Leg::RawUdp], Profile::Smoke).ceiling_leg(),
            None
        );
        let c = caveats(&cfg).join("\n");
        assert!(
            c.contains("byte-ceiling sweep ran only on the udp leg"),
            "{c}"
        );
    }

    /// Reordering measured once is weather, not a property of the path, and the
    /// caveat that says so has to travel with any run that measures it — the two
    /// adjacent runs it quotes are why every reordering claim here needs two
    /// runs before it is a claim.
    #[test]
    fn a_run_that_measures_reordering_says_one_run_cannot_establish_it() {
        let c = caveats(&demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Standard)).join("\n");
        assert!(c.contains("13.4% reordering"), "{c}");
        assert!(c.contains("7.69% loss"), "{c}");
        assert!(c.contains("that run's weather"), "{c}");

        // A run with no raw UDP control measures none of it and must not carry
        // a caveat about a measurement it never took.
        let none = caveats(&demo_cfg(vec![Leg::Udp, Leg::RawTcp], Profile::Standard)).join("\n");
        assert!(!none.contains("reordering"), "{none}");
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
                quic_port: 6,
                raw_tcp_port: 4,
                raw_udp_port: 5,
                raw_udp_down_port: 7,
                raw_udp_up_port: 8,
                sni: "s".into(),
                quic_cert: None,
            },
            pin: vec![0; 64],
            profile,
            legs,
            out_root: PathBuf::from("/tmp"),
            params: Params::for_profile(profile),
            upload_converge: false,
            upload_results: false,
            only: None,
            capture_iface: "any".into(),
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

    /// A round trip bounds the two directions together and neither alone, so a
    /// run needs a one-way control in each. The pair is what makes an `upload`
    /// number and a `download` number statements about the protocol rather than
    /// about whatever the path happened to be doing that minute.
    #[test]
    fn each_direction_has_its_own_one_way_control() {
        for s in ["downstream", "upstream"] {
            assert!(
                RAW_SCENARIOS.contains(&s),
                "{s} must be a scenario the raw legs answer to"
            );
        }
        let mut cfg = demo_cfg(vec![Leg::RawUdp], Profile::Smoke);
        cfg.only = Some(["upstream".to_string()].into_iter().collect());
        assert!(cfg.wants("upstream"));
        assert!(
            cfg.unknown_filters().is_empty(),
            "the uplink ladder's own name is not a typo"
        );

        let c = caveats(&demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Standard)).join("\n");
        assert!(
            c.contains("client -> server"),
            "the direction each one-way control covers must travel with the numbers: {c}"
        );
        assert!(c.contains("server -> client"), "{c}");
        assert!(
            c.contains("neither speaks for the other"),
            "one one-way control is not two: {c}"
        );
    }

    /// Every campaign before this control existed had to record that upload was
    /// measured against nothing. A run that still skips it must say the same
    /// thing rather than leaving the omission to be noticed.
    #[test]
    fn a_run_without_the_upstream_control_says_upload_has_no_denominator() {
        let mut cfg = demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Standard);
        cfg.only = Some(["downstream".to_string()].into_iter().collect());
        let c = caveats(&cfg).join("\n");
        assert!(
            c.contains("No one-way upstream control ran"),
            "the missing denominator must be stated: {c}"
        );
        assert!(
            c.contains("nothing to be normalised against"),
            "and what its absence costs: {c}"
        );
        assert!(!c.contains("No one-way downstream control ran"), "{c}");

        // A run with no raw UDP leg at all loses both, and must say both.
        let neither = caveats(&demo_cfg(vec![Leg::Udp, Leg::RawTcp], Profile::Standard)).join("\n");
        assert!(neither.contains("No one-way upstream control ran"));
        assert!(neither.contains("No one-way downstream control ran"));

        // And a run that has them carries neither complaint.
        let both = caveats(&demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Standard)).join("\n");
        assert!(!both.contains("No one-way"), "{both}");
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

    /// Every scenario the protocol under test runs must be accounted for on the
    /// reference leg — either run, or skipped with a reason recorded in the
    /// artifact. A scenario added later and forgotten here would leave a hole in
    /// the comparison that nothing in the output would reveal.
    #[test]
    fn the_reference_leg_accounts_for_every_scenario() {
        let skipped: Vec<&str> = QUIC_SKIPPED.iter().map(|(s, _)| *s).collect();
        for s in PHANTOM_SCENARIOS {
            let covered = QUIC_COVERED.contains(s);
            let explained = skipped.contains(s);
            assert!(
                covered ^ explained,
                "{s}: must be either run on the reference leg or skipped with a reason, not {}",
                if covered { "both" } else { "neither" }
            );
        }
        for s in QUIC_COVERED.iter().chain(skipped.iter()) {
            assert!(
                PHANTOM_SCENARIOS.contains(s),
                "{s} is not a scenario the matrix runs"
            );
        }
        // The five the measurement turns on must genuinely be in the covered set: they
        // are what makes this a comparison rather than a demonstration.
        for s in ["handshake", "rtt_sweep", "upload", "download", "bidir"] {
            assert!(
                QUIC_COVERED.contains(&s),
                "{s} must run on the reference leg"
            );
        }
    }

    /// Every skipped scenario must carry a reason a reader can act on, not a
    /// shrug.
    #[test]
    fn every_skip_states_a_reason() {
        for (scenario, why) in QUIC_SKIPPED {
            assert!(
                why.len() > 40,
                "{scenario}: a one-word reason is not a reason ({why})"
            );
            let out = scenarios::skipped(Leg::Quic, scenario, why);
            assert_eq!(out.summary.error_count, 0, "a skip is not a failure");
            assert_eq!(out.summary.ok_count, 0);
            assert!(out.sink.is_empty(), "a skip records no samples");
            assert!(
                out.summary.notes.iter().any(|n| n.contains(why)),
                "the reason must reach the artifact"
            );
        }
    }

    /// The caveat that keeps the comparison honest. If it ever stops travelling
    /// with the data, someone will read a 40 ms TLS handshake against a
    /// post-quantum one and conclude something false.
    #[test]
    fn the_reference_leg_states_what_it_does_not_control_for() {
        let with = caveats(&demo_cfg(vec![Leg::Udp, Leg::Quic], Profile::Standard));
        let joined = with.join("\n");
        assert!(
            joined.contains(
                "quinn is TLS 1.3 with classical cryptography, while the protocol under test does a hybrid post-quantum key exchange, so handshake latencies are not comparable like-for-like and the difference is expected. Throughput and loss behaviour are comparable."
            ),
            "the handshake caveat must travel with the numbers verbatim: {joined}"
        );
        assert!(
            joined.contains("Cubic") && joined.contains("BBR"),
            "the congestion-control difference must be stated"
        );
        assert!(
            joined.contains("8 MiB"),
            "the one tuning knob touched must be disclosed"
        );
        assert!(
            joined.contains("verification is not disabled"),
            "what the handshake number means depends on this being said"
        );
        assert!(
            joined.contains("min_rtt_us holds quinn's smoothed RTT"),
            "the field whose meaning differs between legs must be called out"
        );

        // And none of it appears when the leg is not in the run, so a Phantom-only
        // artifact does not carry caveats about a leg it never touched.
        let without = caveats(&demo_cfg(vec![Leg::Udp, Leg::RawUdp], Profile::Standard)).join("\n");
        assert!(!without.contains("quinn"), "{without}");
    }

    /// `--only` must be an exact filter: naming one scenario must not silently
    /// enable a similarly-named neighbour, and omitting it must run everything.
    #[test]
    fn only_filter_is_exact_and_defaults_to_everything() {
        let all = demo_cfg(vec![Leg::Udp], Profile::Smoke);
        for s in PHANTOM_SCENARIOS {
            assert!(all.wants(s), "no filter must run {s}");
        }
        assert!(all.wants("throughput"), "the raw legs' capacity probe too");

        let mut filtered = demo_cfg(vec![Leg::Udp], Profile::Smoke);
        filtered.only = Some(["rtt_sweep".to_string()].into_iter().collect());
        assert!(filtered.wants("rtt_sweep"));
        assert!(!filtered.wants("upload"));
        assert!(!filtered.wants("rtt"), "prefixes must not match");
        assert!(!filtered.wants("rtt_sweep_extra"));
    }

    /// Because the filter is exact, a typo runs nothing at all. Saying so up
    /// front is the difference between a wasted minute and a wasted hour.
    #[test]
    fn a_misspelled_only_filter_is_reported_rather_than_running_nothing() {
        let mut cfg = demo_cfg(vec![Leg::Udp], Profile::Smoke);
        cfg.only = Some(
            ["rtt-sweep".to_string(), "upload".to_string()]
                .into_iter()
                .collect(),
        );
        assert_eq!(cfg.unknown_filters(), vec!["rtt-sweep".to_string()]);

        cfg.only = Some(
            ["rtt_sweep".to_string(), "throughput".to_string()]
                .into_iter()
                .collect(),
        );
        assert!(
            cfg.unknown_filters().is_empty(),
            "the raw legs' own scenario names are not typos"
        );

        let unfiltered = demo_cfg(vec![Leg::Udp], Profile::Smoke);
        assert!(unfiltered.unknown_filters().is_empty());
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
