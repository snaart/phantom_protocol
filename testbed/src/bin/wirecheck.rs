//! `phantom-wirecheck` — is the application's data on the wire, on this machine?
//!
//! Runs a complete PhantomUDP session against a listener in the same process,
//! captures every datagram between them, and searches the capture for the
//! payloads it drove through the session. It takes no arguments, needs no
//! daemon, and needs no privileges — see [`phantom_testbed::wirecheck::loopback`]
//! for how the capture is taken without `tcpdump`, and for the list of things a
//! loopback capture does not settle.
//!
//! ```text
//! cargo run --manifest-path testbed/Cargo.toml --bin phantom-wirecheck
//! cargo run --manifest-path testbed/Cargo.toml --bin phantom-wirecheck -- \
//!     --messages 32 --keep-capture ./wirecheck.pcap
//! ```
//!
//! The exit status is the verdict, so it composes: `0` the check passed, `2` it
//! failed — which includes the case where the search found nothing at all and
//! therefore proved nothing — and `1` the check could not be run.
//!
//! The privileged, real-path version of the same question is the probe's
//! `wire_capture` scenario; this one is deliberately the cheap one that can run
//! everywhere.

use clap::Parser;
use phantom_testbed::wirecheck::{self, loopback, Verdict};

#[derive(Parser, Debug)]
#[command(
    name = "phantom-wirecheck",
    version,
    about = "Search a loopback capture of a live Phantom session for its own application bytes"
)]
struct Args {
    /// Application messages to drive through the session and then search for.
    #[arg(long, default_value_t = loopback::DEFAULT_MESSAGES)]
    messages: usize,

    /// Keep the capture at this path. Without it the capture is analysed in
    /// memory and discarded — the verdict is the same either way, but a kept
    /// file is what lets someone open the evidence in a packet analyser.
    #[arg(long)]
    keep_capture: Option<std::path::PathBuf>,

    /// Print the whole record as JSON instead of as prose, for a caller that
    /// wants to keep it rather than read it.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    if args.messages == 0 {
        eprintln!(
            "--messages 0 would send nothing, and \"no application bytes on the wire\" is \
             vacuous when no application bytes were sent"
        );
        return std::process::ExitCode::from(1);
    }

    let sample = loopback::run(args.messages, args.keep_capture.as_deref()).await;

    if args.json {
        match serde_json::to_string_pretty(&sample) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("the record could not be serialised: {e}");
                return std::process::ExitCode::from(1);
            }
        }
    } else {
        for line in wirecheck::report_lines(&sample) {
            println!("{line}");
        }
    }

    match sample.findings.verdict {
        Verdict::Pass => std::process::ExitCode::SUCCESS,
        Verdict::Failed => std::process::ExitCode::from(2),
        Verdict::Skipped => std::process::ExitCode::from(1),
    }
}
