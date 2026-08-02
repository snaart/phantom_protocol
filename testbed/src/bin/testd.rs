//! `phantom-testd` — the WAN testbed daemon.
//!
//! Binds every network-testable Phantom leg from a single persisted identity,
//! plus raw TCP/UDP echo controls, and records server-side statistics for the
//! duration of the run.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use phantom_testbed::testd::{self, TestdConfig};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(
    name = "phantom-testd",
    version,
    about = "Phantom Protocol WAN testbed daemon"
)]
struct Args {
    /// Phantom-over-TCP listener.
    #[arg(long, env = "TESTD_TCP_BIND", default_value = "0.0.0.0:4242")]
    tcp_bind: SocketAddr,

    /// PhantomUDP listener — the production transport.
    #[arg(long, env = "TESTD_UDP_BIND", default_value = "0.0.0.0:4243")]
    udp_bind: SocketAddr,

    /// mimic-TLS listener.
    #[arg(long, env = "TESTD_MIMIC_BIND", default_value = "0.0.0.0:4244")]
    mimic_bind: SocketAddr,

    /// Raw TCP echo control (no Phantom).
    #[arg(long, env = "TESTD_RAW_TCP_BIND", default_value = "0.0.0.0:4342")]
    raw_tcp_bind: SocketAddr,

    /// Raw UDP echo control (no Phantom).
    #[arg(long, env = "TESTD_RAW_UDP_BIND", default_value = "0.0.0.0:4343")]
    raw_udp_bind: SocketAddr,

    /// Disable the mimic-TLS leg.
    #[arg(long, env = "TESTD_NO_MIMIC")]
    no_mimic: bool,

    /// SNI the mimic-TLS leg presents.
    #[arg(long, env = "TESTD_MIMIC_SNI", default_value = "www.cloudflare.com")]
    mimic_sni: String,

    /// Directory for collected data.
    #[arg(long, env = "TESTD_DATA_DIR", default_value = "/var/lib/phantom-testd")]
    data_dir: PathBuf,

    /// Long-lived signing seed. Created at 0600 on first run.
    #[arg(
        long,
        env = "TESTD_SIGNING_KEY_FILE",
        default_value = "/var/lib/phantom-testd/signing.key"
    )]
    signing_key_file: PathBuf,

    /// Concurrent session ceiling across all legs. Sized for a 2 GB host by
    /// default — raise it deliberately, alongside `LimitNOFILE`.
    #[arg(long, env = "TESTD_MAX_SESSIONS", default_value_t = 512)]
    max_sessions: usize,

    /// Seconds between server-side metric snapshots.
    #[arg(long, env = "TESTD_SNAPSHOT_SECS", default_value_t = 5)]
    snapshot_secs: u64,

    /// Keep-alive PING interval, seconds.
    #[arg(long, env = "TESTD_KEEPALIVE_SECS", default_value_t = 15)]
    keepalive_secs: u64,

    /// `Migrating` → `Dead` timeout, seconds.
    ///
    /// Deliberately far below the `PhantomConfig::server()` preset of 7200 s:
    /// a session death that takes two hours to declare cannot be observed
    /// inside a test run at all.
    #[arg(long, env = "TESTD_SESSION_TIMEOUT_SECS", default_value_t = 120)]
    session_timeout_secs: u64,

    /// Tracing filter.
    #[arg(
        long,
        env = "RUST_LOG",
        default_value = "info,phantom_protocol=info,phantom_testbed=debug"
    )]
    log_filter: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = EnvFilter::try_new(&args.log_filter).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true))
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        data_dir = %args.data_dir.display(),
        "phantom-testd starting"
    );

    testd::run(TestdConfig {
        tcp_bind: args.tcp_bind,
        udp_bind: args.udp_bind,
        mimic_bind: args.mimic_bind,
        raw_tcp_bind: args.raw_tcp_bind,
        raw_udp_bind: args.raw_udp_bind,
        enable_mimic: !args.no_mimic,
        mimic_sni: args.mimic_sni,
        data_dir: args.data_dir,
        signing_key_file: args.signing_key_file,
        max_sessions: args.max_sessions,
        snapshot_interval: Duration::from_secs(args.snapshot_secs.max(1)),
        keepalive: Duration::from_secs(args.keepalive_secs.max(1)),
        session_timeout: Duration::from_secs(args.session_timeout_secs.max(5)),
    })
    .await
}
