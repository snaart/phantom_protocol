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
    ///
    /// `quic` is the reference leg and needs `--quic-cert-file` (or
    /// `--quic-cert-hex`); without one it is skipped with a recorded note
    /// rather than connecting unverified.
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "udp,tcp,mimic,quic,raw_tcp,raw_udp"
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
    #[arg(long, default_value_t = 4245)]
    quic_port: u16,
    #[arg(long, default_value_t = 4342)]
    raw_tcp_port: u16,
    #[arg(long, default_value_t = 4343)]
    raw_udp_port: u16,
    /// The daemon's one-way downstream source (the `downstream` scenario).
    #[arg(long, default_value_t = 4344)]
    raw_udp_down_port: u16,
    /// The daemon's one-way uplink sink (the `upstream` scenario).
    #[arg(long, default_value_t = 4345)]
    raw_udp_up_port: u16,

    /// SNI presented to the mimic-TLS leg. Must match the daemon's.
    #[arg(long, default_value = "www.cloudflare.com")]
    sni: String,

    /// The daemon's QUIC certificate, hex-encoded DER. Logged by the daemon at
    /// boot and written to its data directory as `quic-cert.hex`.
    ///
    /// The probe pins this certificate as its only trust anchor. There is no
    /// flag to skip verification: an unverified handshake would not be
    /// measuring a handshake.
    #[arg(long, env = "PROBE_QUIC_CERT_HEX", conflicts_with = "quic_cert_file")]
    quic_cert_hex: Option<String>,

    /// File containing the daemon's QUIC certificate, hex or raw DER.
    #[arg(long, env = "PROBE_QUIC_CERT_FILE")]
    quic_cert_file: Option<PathBuf>,

    /// Override the profile's soak duration, seconds.
    #[arg(long)]
    soak_secs: Option<u64>,

    /// Override the profile's concurrent-session count.
    #[arg(long)]
    concurrency: Option<usize>,

    /// Override the seconds each bulk upload runs for.
    ///
    /// The default profile windows are short relative to how long a BBR-style
    /// controller takes to converge on a long path: `smoke`'s ten seconds is
    /// about fifty round trips at 200 ms, and a transfer that spends most of
    /// them still raising its own bandwidth estimate reports a convergence rate
    /// under the name of a capacity. Lengthening the window is what separates
    /// the two, and it is the cheapest way to find out which one a given number
    /// was.
    #[arg(long)]
    upload_secs: Option<u64>,

    /// Size each bulk upload from the round trip this run measures, instead of
    /// running a fixed number of seconds.
    ///
    /// Convergence is not counted in seconds. Startup costs round trips, the
    /// gain cycle that follows it raises the bandwidth estimate by a quarter per
    /// four round trips, and both are terms in how long a transfer must run
    /// before its mean rate is a capacity rather than a convergence time — so a
    /// window fixed in seconds gives a long path *less* convergence than a short
    /// one, which is backwards. This derives the window instead: 110 round trips
    /// (16 for Startup, 67 for a 40x climb at 1.25x per four rounds, and a
    /// further quarter so the last quarter of the transfer is a plateau). That
    /// costs 22 s on a 200 ms path and 25 s on a 230 ms path, per upload and
    /// per leg. The derivation is in `probe::converge`.
    ///
    /// Needs `clock_sync`, which is what measures the round trip; a run that
    /// filters it out is refused rather than quietly falling back.
    #[arg(long, conflicts_with = "upload_secs")]
    upload_converge: bool,

    /// Override the bytes the `download` scenario asks the daemon to send.
    ///
    /// The receive and duplex scenarios are bounded by a byte budget where
    /// `upload` is bounded by a clock, and that difference is what made the two
    /// incomparable: at the rates this path gives a receiver, the profile's eight
    /// mebibytes are spent in under twenty seconds — well inside the ramp — so
    /// the mean is a convergence time while the upload beside it is a capacity.
    /// Comparing them produced a misleading "we lose in duplex" reading.
    #[arg(long)]
    download_mib: Option<u64>,

    /// Override the bytes each direction of the `bidir` scenario carries. Same
    /// reason as `--download-mib`: four mebibytes is a fifth of what the
    /// controller needs to converge on this path.
    #[arg(long)]
    bidir_mib: Option<u64>,

    /// Override the wall-clock ceiling on a single bulk transfer, in seconds.
    ///
    /// The byte budgets above and this ceiling are two different ways for a
    /// transfer to end, and whichever comes first is the one that decides.
    /// Raising a budget without raising this does nothing at all on a path slow
    /// enough for the clock to run out first — which is what happened to the
    /// 26 August campaign, where both `download` and `bidir` were cut at 60
    /// seconds having moved between half and a third of the bytes asked for.
    /// Each scenario says so in its own notes, so the run was not silent about
    /// it; but a budget that cannot take effect is worth being able to fix.
    #[arg(long)]
    transfer_cap_secs: Option<u64>,

    /// Override the application frame size used by `upload`, `download` and
    /// `bidir`, in bytes.
    ///
    /// It is the one term that moves the ARQ send buffer's byte ceiling —
    /// `MAX_PENDING_PACKETS` **segments**, so the bytes scale with the frame —
    /// while leaving the peer's flow-control window, a byte bound, exactly
    /// where it was. At the default 1024 the two land within half a percent of
    /// each other and no recorded field tells a sender pinned against one from
    /// a sender pinned against the other; halving this separates them by two.
    #[arg(long)]
    transfer_frame: Option<u32>,

    /// Override the RTT sweep's payload sizes, in bytes. Useful for isolating a
    /// size that misbehaves without re-running the whole sweep.
    #[arg(long, value_delimiter = ',')]
    rtt_sizes: Option<Vec<usize>>,

    /// Override the number of probes per payload size.
    #[arg(long)]
    rtt_per_size: Option<usize>,

    /// Override the raw UDP controls' offered-rate ladder, kbit/s.
    ///
    /// Applies to both directions, so the uplink and downlink rungs stay
    /// comparable. Raise the top of it when the default ladder saturates
    /// nothing — a run where the highest rung was still reached without loss
    /// has not found the ceiling, only a lower bound on it.
    #[arg(long, value_delimiter = ',')]
    raw_rungs_kbps: Option<Vec<u64>>,

    /// Override the seconds spent at each rung of that ladder.
    #[arg(long)]
    raw_rung_secs: Option<u64>,

    /// Run only these scenarios (comma-separated names, e.g. rtt_sweep,upload).
    /// Default: the whole matrix for the chosen profile.
    #[arg(long, value_delimiter = ',')]
    only: Option<Vec<String>>,

    /// Interface the `wire_capture` scenario captures on.
    ///
    /// `any` is a Linux pseudo-interface; macOS and BSD need a real name
    /// (`en0`, `lo0`). Capturing at all needs elevated rights — without them
    /// the scenario records why it was skipped rather than reporting a check it
    /// did not run.
    #[arg(long, default_value = "any")]
    capture_iface: String,

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

    let quic_cert = load_quic_cert(&args)?;

    // Deduplicate while preserving the order the operator asked for — running a
    // leg twice would double its wall clock for no extra information.
    let mut legs: Vec<Leg> = Vec::new();
    for &l in &args.legs {
        if !legs.contains(&l) {
            legs.push(l);
        }
    }
    anyhow::ensure!(!legs.is_empty(), "no legs selected");

    let params = resolved_params(&args)?;

    let cfg = ProbeConfig {
        endpoints: Endpoints {
            host: args.host,
            tcp_port: args.tcp_port,
            udp_port: args.udp_port,
            mimic_port: args.mimic_port,
            quic_port: args.quic_port,
            raw_tcp_port: args.raw_tcp_port,
            raw_udp_port: args.raw_udp_port,
            raw_udp_down_port: args.raw_udp_down_port,
            raw_udp_up_port: args.raw_udp_up_port,
            sni: args.sni,
            quic_cert,
        },
        pin,
        profile: args.profile,
        legs,
        out_root: args.out,
        params,
        upload_converge: args.upload_converge,
        upload_results: !args.no_upload,
        only: args.only.map(|v| v.into_iter().collect()),
        capture_iface: args.capture_iface,
    };

    probe::run(cfg).await?;
    Ok(())
}

/// The profile's knobs with the operator's overrides applied.
///
/// Split out of `main` so the overrides can be exercised without a daemon: they
/// are the levers a measurement is steered with, and one that silently does not
/// take — an upload longer than the wall-clock cap that bounds it, say — costs a
/// run and is invisible in the artifact it produces.
fn resolved_params(args: &Args) -> Result<Params> {
    let mut params = Params::for_profile(args.profile);
    if let Some(s) = args.soak_secs {
        params.soak = Duration::from_secs(s);
    }
    if let Some(c) = args.concurrency {
        params.concurrency = c.max(1);
    }
    if let Some(s) = args.upload_secs {
        anyhow::ensure!(s > 0, "--upload-secs must be at least 1");
        params.upload = Duration::from_secs(s);
        // Widened to match, though on the current wiring it makes no
        // difference: `transfer_cap` is passed only to `download` and `bidir`,
        // while `upload` is bounded by the window above and never sees the cap.
        // The line predates that being checked and is kept because it costs
        // nothing and would be right again the day the cap does reach every
        // bulk transfer — but it is not, today, protecting the upload from
        // anything, and the comment that said it was has been removed rather
        // than left to be believed.
        params.transfer_cap = params.transfer_cap.max(params.upload);
    }
    if let Some(m) = args.download_mib {
        anyhow::ensure!(m > 0, "--download-mib must be at least 1");
        params.download_bytes = m * 1024 * 1024;
    }
    if let Some(m) = args.bidir_mib {
        anyhow::ensure!(m > 0, "--bidir-mib must be at least 1");
        params.bidir_bytes = m * 1024 * 1024;
    }
    if let Some(s) = args.transfer_cap_secs {
        anyhow::ensure!(s > 0, "--transfer-cap-secs must be at least 1");
        // Deliberately **not** checked against `params.upload`, and the reason
        // is worth stating because the neighbouring rule reads as though it
        // should be. `transfer_cap` reaches exactly two scenarios — `download`
        // and `bidir` — and `upload` is bounded by its own window, which the
        // cap never sees. So a cap below the upload window cuts nothing, and
        // refusing that combination would reject a perfectly sensible run: a
        // long upload measured against a short receive.
        //
        // Applied after `--upload-secs`, so an explicit cap wins over the
        // widening that flag performs.
        params.transfer_cap = Duration::from_secs(s);
    }
    if let Some(f) = args.transfer_frame {
        // The sink message carries a length prefix, a verb and a sequence
        // number before any payload; below that the frame is header alone.
        anyhow::ensure!(f >= 64, "--transfer-frame must be at least 64 bytes");
        params.transfer_frame = f;
    }
    if let Some(sizes) = &args.rtt_sizes {
        anyhow::ensure!(!sizes.is_empty(), "--rtt-sizes cannot be empty");
        params.rtt_sizes = sizes.clone();
    }
    if let Some(n) = args.rtt_per_size {
        params.rtt_per_size = n.max(1);
    }
    if let Some(rungs) = &args.raw_rungs_kbps {
        anyhow::ensure!(!rungs.is_empty(), "--raw-rungs-kbps cannot be empty");
        anyhow::ensure!(
            rungs.iter().all(|&r| r > 0),
            "--raw-rungs-kbps must be positive rates"
        );
        params.raw_rungs_kbps = rungs.clone();
    }
    if let Some(s) = args.raw_rung_secs {
        anyhow::ensure!(s > 0, "--raw-rung-secs must be at least 1");
        params.raw_rate_step = Duration::from_secs(s);
    }
    Ok(params)
}

/// Resolve the QUIC certificate pin, if one was supplied.
///
/// Accepts hex or raw DER from a file, because the daemon writes both
/// (`quic-cert.hex` and `quic-cert.der`) and an operator copying one of them
/// should not have to know which the probe wanted. `None` — no pin — is not an
/// error: the run proceeds and the reference leg records why it was skipped.
fn load_quic_cert(args: &Args) -> Result<Option<Vec<u8>>> {
    let raw = match (&args.quic_cert_hex, &args.quic_cert_file) {
        (Some(h), _) => h.trim().as_bytes().to_vec(),
        (None, Some(f)) => {
            std::fs::read(f).with_context(|| format!("read QUIC cert file {}", f.display()))?
        }
        (None, None) => return Ok(None),
    };

    // A DER certificate always starts with a SEQUENCE tag (0x30); hex text
    // never does. That is a cheaper and more reliable discriminator than
    // guessing from the file extension.
    if raw.first() == Some(&0x30) {
        anyhow::ensure!(!raw.is_empty(), "QUIC certificate is empty");
        return Ok(Some(raw));
    }
    let text = String::from_utf8(raw).context("QUIC certificate is neither DER nor text")?;
    let der = hex::decode(text.trim()).context("QUIC certificate is not valid hex")?;
    anyhow::ensure!(!der.is_empty(), "QUIC certificate is empty");
    Ok(Some(der))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest command line the parser accepts, plus whatever is under test.
    fn parse(extra: &[&str]) -> Args {
        let mut argv = vec![
            "phantom-probe",
            "--host",
            "example.invalid",
            "--pin-hex",
            "aa",
        ];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv).expect("the parser must accept this command line")
    }

    #[test]
    fn a_longer_upload_carries_the_wall_clock_cap_that_bounds_it_upward() {
        // `smoke` runs a 10 s upload under a 60 s cap. Asking for 180 s without
        // moving the cap would run 60 and record it as if it had run 180 — the
        // shape of override that is invisible in the artifact it produced.
        let p = resolved_params(&parse(&["--upload-secs", "180"])).expect("override must apply");
        assert_eq!(p.upload, Duration::from_secs(180));
        assert!(
            p.transfer_cap >= p.upload,
            "the cap must not silently truncate the window that was asked for: \
             cap {:?} < upload {:?}",
            p.transfer_cap,
            p.upload
        );
    }

    #[test]
    fn a_shorter_upload_leaves_the_cap_where_the_profile_put_it() {
        let base = Params::for_profile(Profile::Smoke).transfer_cap;
        let p = resolved_params(&parse(&["--upload-secs", "5"])).expect("override must apply");
        assert_eq!(p.upload, Duration::from_secs(5));
        assert_eq!(
            p.transfer_cap, base,
            "a shorter upload is no reason to widen the cap"
        );
    }

    #[test]
    fn the_transfer_frame_override_reaches_the_bulk_scenarios() {
        // This is the one knob that separates the ARQ send buffer's ceiling — a
        // segment count, so its byte figure scales with the frame — from the
        // peer's flow-control window, which is a byte figure that does not.
        let p = resolved_params(&parse(&["--transfer-frame", "512"])).expect("override must apply");
        assert_eq!(p.transfer_frame, 512);
    }

    /// The receive and duplex budgets are counted in bytes where the upload's is
    /// counted in seconds, and at this path's rates the profile's eight and four
    /// mebibytes are spent inside the ramp. Without a way to raise them the two
    /// halves of a duplex comparison are a capacity and a convergence time, which
    /// is the comparison the misleading duplex reading was built on.
    #[test]
    fn the_receive_and_duplex_budgets_can_be_raised() {
        let p = resolved_params(&parse(&["--download-mib", "150"])).expect("override must apply");
        assert_eq!(p.download_bytes, 150 * 1024 * 1024);
        let p = resolved_params(&parse(&["--bidir-mib", "120"])).expect("override must apply");
        assert_eq!(p.bidir_bytes, 120 * 1024 * 1024);
        // And each leaves the other alone.
        let base = resolved_params(&parse(&[])).expect("defaults");
        let only_down =
            resolved_params(&parse(&["--download-mib", "150"])).expect("override must apply");
        assert_eq!(only_down.bidir_bytes, base.bidir_bytes);
    }

    /// A byte budget and the wall-clock cap are two ways for one transfer to
    /// end, and the smaller decides. Raising a budget on a path slow enough for
    /// the clock to win first therefore changes nothing, which is what the 26
    /// August campaign ran into: 150 and 120 mebibytes asked for, between a
    /// third and a half of them moved, every scenario cut at sixty seconds.
    #[test]
    fn the_measurement_window_can_be_raised_alongside_the_byte_budgets() {
        let base = resolved_params(&parse(&[])).expect("defaults");
        let p = resolved_params(&parse(&["--transfer-cap-secs", "180"])).expect("override applies");
        assert_eq!(p.transfer_cap, Duration::from_secs(180));
        assert!(
            p.transfer_cap > base.transfer_cap,
            "the override has to actually widen the window it names"
        );
        // Raising the cap is not a reason to move anything else.
        assert_eq!(p.download_bytes, base.download_bytes);
        assert_eq!(p.upload, base.upload);

        // An override has to be able to move its value in **both** directions,
        // or it is a widening and should say so in its name. A `.max()` against
        // the profile default would pass every assertion above and silently
        // ignore any cap below sixty seconds.
        let lowered =
            resolved_params(&parse(&["--transfer-cap-secs", "30"])).expect("override applies");
        assert_eq!(
            lowered.transfer_cap,
            Duration::from_secs(30),
            "a cap below the profile's default has to take effect too, or the flag \
             is a widening wearing the name of an override"
        );

        // The two clock overrides interact, and the rule is *not* the one it
        // looks like: an explicit cap below the upload window is accepted,
        // because `transfer_cap` reaches only `download` and `bidir` and cannot
        // cut an upload short. A long upload measured against a short receive
        // is a sensible run and refusing it would be the tool inventing a
        // constraint the code does not have.
        let both = resolved_params(&parse(&[
            "--upload-secs",
            "120",
            "--transfer-cap-secs",
            "60",
        ]))
        .expect("a cap under the upload window cuts nothing and must be accepted");
        assert_eq!(both.upload, Duration::from_secs(120));
        assert_eq!(both.transfer_cap, Duration::from_secs(60));

        // Order matters between them: `--upload-secs` widens the cap, and an
        // explicit cap is the more specific instruction, so it has to win
        // regardless of the order the two are parsed in.
        let widened_then_set = resolved_params(&parse(&[
            "--upload-secs",
            "300",
            "--transfer-cap-secs",
            "90",
        ]))
        .expect("override applies");
        assert_eq!(
            widened_then_set.transfer_cap,
            Duration::from_secs(90),
            "--upload-secs widened the cap to 300 s and the explicit --transfer-cap-secs \
             did not override it"
        );

        // Zero is refused here rather than somewhere downstream. Asserting only
        // `is_err()` would pass while a neighbouring guard did the refusing for
        // an unrelated reason, so the message is checked too.
        let zero = resolved_params(&parse(&["--transfer-cap-secs", "0"]));
        let why = zero
            .expect_err("a zero-second window measures nothing")
            .to_string();
        assert!(
            why.contains("--transfer-cap-secs"),
            "zero was refused by something other than this flag's own guard: {why}"
        );
    }

    #[test]
    fn overrides_that_would_produce_an_unmeasurable_run_are_refused() {
        for argv in [
            vec!["--upload-secs", "0"],
            vec!["--transfer-frame", "8"],
            vec!["--download-mib", "0"],
            vec!["--bidir-mib", "0"],
            vec!["--raw-rung-secs", "0"],
        ] {
            assert!(
                resolved_params(&parse(&argv)).is_err(),
                "{argv:?} must be refused rather than silently clamped"
            );
        }
    }

    /// The two ways of setting the upload window are exclusive, because they
    /// answer the same question differently and the loser would be invisible.
    #[test]
    fn the_window_cannot_be_both_derived_and_fixed() {
        assert!(
            Args::try_parse_from([
                "phantom-probe",
                "--host",
                "example.invalid",
                "--pin-hex",
                "aa",
                "--upload-secs",
                "60",
                "--upload-converge",
            ])
            .is_err(),
            "a fixed window and a derived one cannot both apply"
        );
        assert!(parse(&["--upload-converge"]).upload_converge);
        assert!(!parse(&[]).upload_converge);
    }

    /// The flag's help states what a converged upload costs in wall clock, and
    /// an operator budgets a run against that figure. It has to be the number
    /// the derivation produces rather than one written down beside it.
    #[test]
    fn the_help_states_the_wall_clock_the_derivation_actually_produces() {
        use clap::CommandFactory;
        let help = Args::command().render_long_help().to_string();
        // Rendered help wraps to the terminal, so compare against a form with
        // the line breaks taken out.
        let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
        for ms in [200u64, 230] {
            let cost = phantom_testbed::probe::converge::cost_at(Duration::from_millis(ms));
            let claim = format!("{:.0} s on a {ms} ms path", cost.as_secs_f64());
            assert!(
                flat.contains(&claim),
                "the help must state the derived cost verbatim; missing {claim:?}"
            );
        }
    }

    #[test]
    fn an_untouched_command_line_is_exactly_the_profile() {
        let p = resolved_params(&parse(&[])).expect("no overrides must apply cleanly");
        let base = Params::for_profile(Profile::Smoke);
        assert_eq!(p.upload, base.upload);
        assert_eq!(p.transfer_frame, base.transfer_frame);
        assert_eq!(p.transfer_cap, base.transfer_cap);
    }
}
