//! Command-line + environment configuration for `phantom-server`.
//!
//! Every flag has both a CLI form (e.g. `--bind`) and an environment
//! fallback (e.g. `PHANTOM_BIND`). The env fallback is what
//! systemd/docker/kubernetes deployments use; the CLI form is for
//! local development.

use clap::Parser;
use phantom_protocol::transport::stream::SESSION_RECV_WINDOW_GROWTH_BUDGET;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "phantom-server",
    version,
    about = "Phantom Protocol reference server"
)]
pub struct Config {
    /// Bind address for the Phantom Protocol transport (TCP).
    #[arg(long, env = "PHANTOM_BIND", default_value = "0.0.0.0:4242")]
    pub bind: SocketAddr,

    /// Path to the long-lived HybridSigningKey blob. Created on first run if
    /// missing. Permissions are tightened to 0600 on Unix.
    #[arg(
        long,
        env = "PHANTOM_SIGNING_KEY_FILE",
        default_value = "/etc/phantom-server/signing.key"
    )]
    pub signing_key_file: PathBuf,

    /// OTLP/gRPC endpoint for OpenTelemetry metrics + traces export.
    ///
    /// Default targets a local OTel Collector. Override for Datadog /
    /// Honeycomb / Grafana Cloud direct endpoints (and set
    /// `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer ...` for auth).
    #[arg(
        long,
        env = "OTEL_EXPORTER_OTLP_ENDPOINT",
        default_value = "http://localhost:4317"
    )]
    pub otlp_endpoint: String,

    /// Trace sampling ratio (0.0 — 1.0), applied to **root** spans.
    ///
    /// Installed directly as `Sampler::ParentBased(TraceIdRatioBased(ratio))`
    /// in [`crate::telemetry`], so both the flag and its `OTEL_TRACES_SAMPLER_ARG`
    /// env fallback take effect without also having to set `OTEL_TRACES_SAMPLER`.
    /// `ParentBased` means an upstream sampling decision is honored, so a trace
    /// sampled by a caller is never truncated here; the ratio gates root spans
    /// only. Values outside `0.0..=1.0` are clamped.
    ///
    /// Defaults to `1.0` (sample everything) to match the behaviour that shipped
    /// while this flag was inert — lower it deliberately, e.g. `0.01` for a 1%
    /// production baseline.
    #[arg(long, env = "OTEL_TRACES_SAMPLER_ARG", default_value = "1.0")]
    pub otel_trace_sample_ratio: f64,

    /// Service name reported via OTel Resource. Defaults to the binary
    /// name; override per-instance for multi-tenant deployments.
    #[arg(long, env = "OTEL_SERVICE_NAME", default_value = "phantom-server")]
    pub otel_service_name: String,

    /// Output structured JSON logs (default: pretty when stdout is a TTY).
    #[arg(long, env = "PHANTOM_LOG_JSON")]
    pub log_json: bool,

    /// Tracing filter (default: info,phantom_protocol=debug).
    #[arg(long, env = "RUST_LOG", default_value = "info,phantom_protocol=debug")]
    pub log_filter: String,

    /// Maximum number of concurrent sessions. Once this many are active the
    /// accept loop stops accepting (new connections queue in the OS backlog)
    /// until a session closes — backpressure, not a hard drop.
    ///
    /// This is the process's memory setting whether or not it was set as one: the
    /// transport bounds its receive buffers per session and nothing divides them
    /// between concurrent sessions, so what a process holds is this number times
    /// what one session holds. There is no single library constant for the second
    /// factor — see the receive-memory section of `phantom_protocol::api::session`
    /// for why, and `docs/operations/deployment.md` for how to size against it.
    /// One term of it does have a constant, and the cap times that constant is
    /// logged at startup ([`Config::recv_window_growth_commitment_mib`]) so the
    /// arithmetic is in front of whoever set this number.
    /// Also keep it comfortably below `LimitNOFILE`. `0` means unbounded (not
    /// recommended).
    #[arg(long, env = "PHANTOM_MAX_SESSIONS", default_value = "1024")]
    pub max_sessions: usize,

    /// Maximum concurrent sessions from a single source IP. A peer already at
    /// this many active sessions has further connections rejected (closed right
    /// after the handshake) so one source cannot monopolise the global pool.
    /// `0` disables the per-IP cap.
    #[arg(long, env = "PHANTOM_MAX_SESSIONS_PER_IP", default_value = "64")]
    pub max_sessions_per_ip: usize,
}

impl Config {
    /// Receive-window growth this process commits at the configured session cap, rendered
    /// for the startup log.
    ///
    /// The transport hands each session `SESSION_RECV_WINDOW_GROWTH_BUDGET` of receive-window
    /// growth to spend across all of its streams and divides that between concurrent sessions
    /// not at all, so the product is exact rather than an estimate — the only receive-side
    /// figure about this process that is. It is stated here, in the log, rather than offered
    /// as a knob, and the distinction is the whole design:
    ///
    /// - **It is a floor on what the host must have, not a ceiling on what the process will
    ///   use.** Growth is one term of a session's receive footprint and not the largest;
    ///   `docs/operations/deployment.md` ranks the reorder structure and the delivery queues
    ///   an order of magnitude above it. Growth is also an *advertisement* — the right to
    ///   have that much outstanding — while the bytes it admits come to rest in those other
    ///   buffers.
    /// - A flag that divided an operator's MiB by this constant to derive a session cap was
    ///   tried and removed. Twice now, in two forms: the first divided by a per-session
    ///   *total* that was an estimate, the second by this enforced constant. The second is
    ///   arithmetically sound and still wrong to offer, because its unit is MiB — an operator
    ///   reaches for a MiB-denominated server flag with a memory limit in hand, so what it is
    ///   handed is a memory limit and what it returns is a session cap that same memory cannot
    ///   support. A knob whose documentation has to say "do not read this as its unit reads"
    ///   should be a log line instead, which is what this is. Size `--max-sessions` by
    ///   measurement.
    ///
    /// `None` when the cap is unbounded: the product does not exist, and rendering it as `0`
    /// would read as "commits nothing" — the opposite of what an unbounded cap means.
    pub fn recv_window_growth_commitment_mib(&self) -> Option<u64> {
        if self.max_sessions == 0 {
            return None;
        }
        Some(
            (self.max_sessions as u64).saturating_mul(u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET))
                / (1024 * 1024),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max_sessions: usize) -> Config {
        Config {
            bind: "0.0.0.0:4242".parse().expect("literal bind address"),
            signing_key_file: PathBuf::from("/dev/null"),
            otlp_endpoint: String::new(),
            otel_trace_sample_ratio: 1.0,
            otel_service_name: String::new(),
            log_json: false,
            log_filter: String::new(),
            max_sessions,
            max_sessions_per_ip: 0,
        }
    }

    /// The published arithmetic, computed by the binary that admits the sessions rather than
    /// restated from a document. The shipped default of 1024 sessions is 8 GiB — the figure
    /// `docs/operations/deployment.md`, `docs/security/threat-model.md` and `CHANGELOG.md`
    /// all print, and `scripts/check_memory_arithmetic.py` is what keeps those copies of it
    /// tied to this one.
    #[test]
    fn the_default_cap_commits_the_published_growth_figure() {
        assert_eq!(
            cfg(1024).recv_window_growth_commitment_mib(),
            Some(8 * 1024)
        );
    }

    /// It is a product, so it tracks the cap. An operator who halves the cap has halved this.
    #[test]
    fn the_commitment_tracks_the_cap_it_is_derived_from() {
        assert_eq!(cfg(1).recv_window_growth_commitment_mib(), Some(8));
        assert_eq!(cfg(512).recv_window_growth_commitment_mib(), Some(4 * 1024));
    }

    /// An unbounded cap has no product, and reporting `0` for it would read as "commits
    /// nothing" — precisely backwards.
    #[test]
    fn an_unbounded_cap_has_no_commitment_to_report() {
        assert_eq!(cfg(0).recv_window_growth_commitment_mib(), None);
    }
}
