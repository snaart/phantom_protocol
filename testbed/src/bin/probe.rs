//! `phantom-probe` — the WAN testbed client.
//!
//! Drives the scenario matrix across the selected legs and writes raw
//! per-operation samples plus a derived summary. Designed to run unattended:
//! every operation is bounded by a timeout, and results are flushed after each
//! scenario, so an interrupted run still yields everything completed so far.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use phantom_testbed::probe::conn::Endpoints;
use phantom_testbed::probe::{self, Params, ProbeConfig, Profile};
use phantom_testbed::report::Leg;

#[derive(Parser, Debug)]
#[command(
    name = "phantom-probe",
    version,
    about = "Phantom Protocol WAN testbed probe"
)]
struct Args {
    /// Server hostname or IP.
    #[arg(long, env = "PROBE_HOST")]
    host: String,

    /// Server verifying key, hex. Printed by the daemon at boot and written to
    /// its data directory as `pin.hex`.
    #[arg(long, env = "PROBE_PIN_HEX", conflicts_with = "pin_file")]
    pin_hex: Option<String>,

    /// File containing the verifying-key hex.
    #[arg(long, env = "PROBE_PIN_FILE")]
    pin_file: Option<PathBuf>,

    /// Test intensity.
    #[arg(long, value_enum, default_value_t = Profile::Smoke)]
    profile: Profile,

    /// Legs to exercise, in order.
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "udp,tcp,mimic,raw_tcp,raw_udp"
    )]
    legs: Vec<Leg>,

    /// Output directory root; each run creates a timestamped subdirectory.
    #[arg(long, default_value = "./results")]
    out: PathBuf,

    #[arg(long, default_value_t = 4242)]
    tcp_port: u16,
    #[arg(long, default_value_t = 4243)]
    udp_port: u16,
    #[arg(long, default_value_t = 4244)]
    mimic_port: u16,
    #[arg(long, default_value_t = 4342)]
    raw_tcp_port: u16,
    #[arg(long, default_value_t = 4343)]
    raw_udp_port: u16,

    /// SNI presented to the mimic-TLS leg. Must match the daemon's.
    #[arg(long, default_value = "www.cloudflare.com")]
    sni: String,

    /// Override the profile's soak duration, seconds.
    #[arg(long)]
    soak_secs: Option<u64>,

    /// Override the profile's concurrent-session count.
    #[arg(long)]
    concurrency: Option<usize>,

    /// Override the RTT sweep's payload sizes, in bytes. Useful for isolating a
    /// size that misbehaves without re-running the whole sweep.
    #[arg(long, value_delimiter = ',')]
    rtt_sizes: Option<Vec<usize>>,

    /// Override the number of probes per payload size.
    #[arg(long)]
    rtt_per_size: Option<usize>,

    /// Run only these scenarios (comma-separated names, e.g. rtt_sweep,upload).
    /// Default: the whole matrix for the chosen profile.
    #[arg(long, value_delimiter = ',')]
    only: Option<Vec<String>>,

    /// Skip uploading the result bundle back to the daemon.
    #[arg(long)]
    no_upload: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let pin_hex = match (&args.pin_hex, &args.pin_file) {
        (Some(h), _) => h.trim().to_string(),
        (None, Some(f)) => std::fs::read_to_string(f)
            .with_context(|| format!("read pin file {}", f.display()))?
            .trim()
            .to_string(),
        (None, None) => anyhow::bail!("one of --pin-hex or --pin-file is required"),
    };
    let pin = hex::decode(&pin_hex).context("pin is not valid hex")?;
    anyhow::ensure!(!pin.is_empty(), "pin is empty");

    // Deduplicate while preserving the order the operator asked for — running a
    // leg twice would double its wall clock for no extra information.
    let mut legs: Vec<Leg> = Vec::new();
    for l in args.legs {
        if !legs.contains(&l) {
            legs.push(l);
        }
    }
    anyhow::ensure!(!legs.is_empty(), "no legs selected");

    let mut params = Params::for_profile(args.profile);
    if let Some(s) = args.soak_secs {
        params.soak = Duration::from_secs(s);
    }
    if let Some(c) = args.concurrency {
        params.concurrency = c.max(1);
    }
    if let Some(sizes) = args.rtt_sizes {
        anyhow::ensure!(!sizes.is_empty(), "--rtt-sizes cannot be empty");
        params.rtt_sizes = sizes;
    }
    if let Some(n) = args.rtt_per_size {
        params.rtt_per_size = n.max(1);
    }

    let cfg = ProbeConfig {
        endpoints: Endpoints {
            host: args.host,
            tcp_port: args.tcp_port,
            udp_port: args.udp_port,
            mimic_port: args.mimic_port,
            raw_tcp_port: args.raw_tcp_port,
            raw_udp_port: args.raw_udp_port,
            sni: args.sni,
        },
        pin,
        profile: args.profile,
        legs,
        out_root: args.out,
        params,
        upload_results: !args.no_upload,
        only: args.only.map(|v| v.into_iter().collect()),
    };

    probe::run(cfg).await?;
    Ok(())
}
