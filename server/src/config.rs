//! Command-line + environment configuration for `phantom-server`.
//!
//! Every flag has both a CLI form (e.g. `--bind`) and an environment
//! fallback (e.g. `PHANTOM_BIND`). The env fallback is what
//! systemd/docker/kubernetes deployments use; the CLI form is for
//! local development.

use clap::Parser;
use phantom_protocol::api::session::SESSION_RECV_MEMORY_COMMITMENT;
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
    /// until a session closes — backpressure, not a hard drop. Size it against
    /// `LimitNOFILE` and per-session memory — see `--max-recv-memory-mib` and
    /// `docs/operations/deployment.md`. `0` means unbounded (not recommended).
    #[arg(long, env = "PHANTOM_MAX_SESSIONS", default_value = "1024")]
    pub max_sessions: usize,

    /// Receive-side memory this process may commit to peers, in MiB. `0` (the
    /// default) states no budget and leaves `--max-sessions` alone.
    ///
    /// The transport's receive buffers are bounded **per session**, not per
    /// process: a session's advertised windows, reorder buffers and delivery
    /// backlog together come to `SESSION_RECV_MEMORY_COMMITMENT`, and every term
    /// is something an authenticated peer chooses. Nothing divides that between
    /// concurrent sessions, so the only thing that bounds the process is how many
    /// sessions it admits — which makes the session cap a memory setting whether
    /// or not it is written as one.
    ///
    /// Setting this ties the two together: the cap is lowered to the largest
    /// number of sessions that fits the stated budget, and a budget too small for
    /// even one session refuses to start rather than admitting one anyway.
    #[arg(long, env = "PHANTOM_MAX_RECV_MEMORY_MIB", default_value = "0")]
    pub max_recv_memory_mib: usize,

    /// Maximum concurrent sessions from a single source IP. A peer already at
    /// this many active sessions has further connections rejected (closed right
    /// after the handshake) so one source cannot monopolise the global pool.
    /// `0` disables the per-IP cap.
    #[arg(long, env = "PHANTOM_MAX_SESSIONS_PER_IP", default_value = "64")]
    pub max_sessions_per_ip: usize,
}

impl Config {
    /// The session cap actually enforced, after `--max-recv-memory-mib` has been applied.
    ///
    /// Returns `Err` when the stated receive-memory budget cannot hold a single session:
    /// admitting one anyway would put the process over the figure the operator sized the
    /// host with, which is exactly what stating a budget was meant to prevent.
    pub fn effective_max_sessions(&self) -> Result<usize, String> {
        if self.max_recv_memory_mib == 0 {
            return Ok(self.max_sessions);
        }
        let budget = (self.max_recv_memory_mib as u64).saturating_mul(1024 * 1024);
        let fits = budget / SESSION_RECV_MEMORY_COMMITMENT;
        if fits == 0 {
            return Err(format!(
                "--max-recv-memory-mib {} is below the {} MiB one session may commit; raise the \
                 budget, or state none and size the host from --max-sessions",
                self.max_recv_memory_mib,
                SESSION_RECV_MEMORY_COMMITMENT.div_ceil(1024 * 1024)
            ));
        }
        // `usize` is at least 32 bits on every target this binary builds for, and `fits` is a
        // session count divided down from a budget an operator typed, so the clamp is a
        // formality rather than a reachable path.
        let fits = usize::try_from(fits).unwrap_or(usize::MAX);
        Ok(if self.max_sessions == 0 {
            // Unbounded means "no cap of my own"; the budget then supplies one.
            fits
        } else {
            self.max_sessions.min(fits)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max_sessions: usize, max_recv_memory_mib: usize) -> Config {
        Config {
            bind: "0.0.0.0:4242".parse().expect("bind addr"),
            signing_key_file: PathBuf::from("/dev/null"),
            otlp_endpoint: String::new(),
            otel_trace_sample_ratio: 1.0,
            otel_service_name: String::new(),
            log_json: false,
            log_filter: String::new(),
            max_sessions,
            max_recv_memory_mib,
            max_sessions_per_ip: 0,
        }
    }

    fn per_session_mib() -> usize {
        (SESSION_RECV_MEMORY_COMMITMENT / (1024 * 1024)) as usize
    }

    /// The flag is opt-in: with no budget stated the operator's cap stands exactly as typed,
    /// including the unbounded form.
    #[test]
    fn no_budget_leaves_the_session_cap_alone() {
        assert_eq!(cfg(1024, 0).effective_max_sessions(), Ok(1024));
        assert_eq!(cfg(0, 0).effective_max_sessions(), Ok(0));
    }

    /// The point of the flag: a budget that cannot hold the default 1024 sessions lowers the
    /// cap to what it can hold, so the process commitment stays under the stated figure.
    #[test]
    fn a_budget_lowers_the_cap_to_what_it_can_hold() {
        let ten_sessions = 10 * per_session_mib();
        assert_eq!(cfg(1024, ten_sessions).effective_max_sessions(), Ok(10));
        // An unbounded cap takes the budget's answer rather than staying unbounded — that
        // combination is the one where the memory bound has nothing else to come from.
        assert_eq!(cfg(0, ten_sessions).effective_max_sessions(), Ok(10));
    }

    /// A generous budget is not licence to raise the cap: the operator asked for at most
    /// `max_sessions`, and the memory figure is a ceiling rather than a target.
    #[test]
    fn a_generous_budget_does_not_raise_the_cap() {
        assert_eq!(
            cfg(8, 1000 * per_session_mib()).effective_max_sessions(),
            Ok(8)
        );
    }

    /// A budget below one session's commitment refuses to start. Admitting one session
    /// anyway would put the process over the figure the host was sized with, quietly.
    #[test]
    fn a_budget_too_small_for_one_session_is_refused() {
        let err = cfg(1024, 1)
            .effective_max_sessions()
            .expect_err("a budget that cannot hold one session must refuse");
        assert!(err.contains("below"), "unhelpful message: {err}");
    }
}
