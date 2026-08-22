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
    /// One term of it does have a constant, and `--max-recv-window-growth-mib`
    /// derives this cap from that term rather than the other way round.
    /// Also keep it comfortably below `LimitNOFILE`. `0` means unbounded (not
    /// recommended).
    #[arg(long, env = "PHANTOM_MAX_SESSIONS", default_value = "1024")]
    pub max_sessions: usize,

    /// Ceiling on the receive-window **growth** this process will commit to peers, in MiB.
    /// `0` (the default) states no ceiling and leaves `--max-sessions` exactly as typed.
    ///
    /// Receive-window growth is the one receive-side quantity with an enforced per-session
    /// constant behind it: a session may hand out `SESSION_RECV_WINDOW_GROWTH_BUDGET`
    /// (8 MiB) of window growth across all of its streams, however many it opens, and
    /// nothing divides that between concurrent sessions. So a process admitting `N`
    /// sessions commits `N × 8 MiB` of it — 8 GiB at the default cap of 1024. Stating a
    /// ceiling here lowers `--max-sessions` to the sessions that fit inside it, and a
    /// ceiling too small for even one session refuses to start rather than admitting one
    /// anyway.
    ///
    /// **This is a floor on what the host must have, not a ceiling on what it will use.**
    /// Window growth is one term of a session's receive footprint; the reorder buffers, the
    /// delivery backlog and the per-stream delivery queues are separately bounded and are
    /// individually larger. No single library constant totals them — see the receive-memory
    /// section of `phantom_protocol::api::session` for why one was published, corrected
    /// upward three times, and then withdrawn. Sizing a host still ends in measurement
    /// against the deployment's own traffic (`docs/operations/deployment.md`); what this
    /// flag adds is a configuration that cannot be wrong in the cheap direction, because a
    /// cap whose growth commitment alone exceeds the host is wrong before any measurement
    /// is taken.
    #[arg(long, env = "PHANTOM_MAX_RECV_WINDOW_GROWTH_MIB", default_value = "0")]
    pub max_recv_window_growth_mib: usize,

    /// Maximum concurrent sessions from a single source IP. A peer already at
    /// this many active sessions has further connections rejected (closed right
    /// after the handshake) so one source cannot monopolise the global pool.
    /// `0` disables the per-IP cap.
    #[arg(long, env = "PHANTOM_MAX_SESSIONS_PER_IP", default_value = "64")]
    pub max_sessions_per_ip: usize,
}

impl Config {
    /// The session cap actually enforced, once `--max-recv-window-growth-mib` has been
    /// applied to it.
    ///
    /// Returns `Err` when the stated ceiling cannot hold a single session's growth
    /// allowance. Admitting one session anyway would put the process past the figure the
    /// operator wrote down, silently, which is the outcome writing it down was meant to
    /// rule out — and a server that starts having quietly discarded a limit is worse than
    /// one that refuses and says which limit.
    pub fn effective_max_sessions(&self) -> Result<usize, String> {
        if self.max_recv_window_growth_mib == 0 {
            return Ok(self.max_sessions);
        }
        let ceiling = (self.max_recv_window_growth_mib as u64).saturating_mul(1024 * 1024);
        let fits = ceiling / u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET);
        if fits == 0 {
            return Err(format!(
                "--max-recv-window-growth-mib {} is below the {} MiB of window growth one \
                 session may draw; raise it, or state none and size --max-sessions by \
                 measurement",
                self.max_recv_window_growth_mib,
                SESSION_RECV_WINDOW_GROWTH_BUDGET.div_ceil(1024 * 1024)
            ));
        }
        // `fits` is a ceiling an operator typed divided by 8 MiB, so on any target this
        // binary is built for it is far inside `usize`; the conversion is written as a
        // saturating one rather than a cast so that a 32-bit host cannot turn an absurd
        // ceiling into a small cap by wrapping.
        let fits = usize::try_from(fits).unwrap_or(usize::MAX);
        Ok(if self.max_sessions == 0 {
            // "Unbounded" means the operator supplied no cap of their own, so the ceiling
            // supplies one. This is the combination where the growth arithmetic is the only
            // thing standing between the process and its memory.
            fits
        } else {
            // A generous ceiling is not licence to admit more than was asked for: the two
            // are both upper bounds, so the enforced cap is the lower of them.
            self.max_sessions.min(fits)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max_sessions: usize, max_recv_window_growth_mib: usize) -> Config {
        Config {
            bind: "0.0.0.0:4242".parse().expect("literal bind address"),
            signing_key_file: PathBuf::from("/dev/null"),
            otlp_endpoint: String::new(),
            otel_trace_sample_ratio: 1.0,
            otel_service_name: String::new(),
            log_json: false,
            log_filter: String::new(),
            max_sessions,
            max_recv_window_growth_mib,
            max_sessions_per_ip: 0,
        }
    }

    /// The allowance a session may draw, in MiB — the divisor the flag works in.
    fn per_session_mib() -> usize {
        SESSION_RECV_WINDOW_GROWTH_BUDGET as usize / (1024 * 1024)
    }

    /// Opt-in: with no budget stated the operator's cap stands exactly as typed, unbounded
    /// form included. Nobody's existing configuration changes because this flag exists.
    #[test]
    fn no_budget_leaves_the_session_cap_alone() {
        assert_eq!(cfg(1024, 0).effective_max_sessions(), Ok(1024));
        assert_eq!(cfg(0, 0).effective_max_sessions(), Ok(0));
    }

    /// The arithmetic the flag exists for: a stated budget divided by the per-session
    /// allowance is the number of sessions whose growth fits inside it.
    #[test]
    fn a_budget_lowers_the_cap_to_the_sessions_whose_growth_fits() {
        let ten = 10 * per_session_mib();
        assert_eq!(cfg(1024, ten).effective_max_sessions(), Ok(10));
        // An unbounded cap takes the budget's answer: that combination is precisely the one
        // where nothing else supplies a bound.
        assert_eq!(cfg(0, ten).effective_max_sessions(), Ok(10));
    }

    /// The default cap and the published process figure are the same statement, so the flag
    /// has to agree with the documents: 8 GiB of stated budget must buy exactly the 1024
    /// sessions `PHANTOM_MAX_SESSIONS` defaults to.
    #[test]
    fn the_published_default_arithmetic_round_trips_through_the_flag() {
        assert_eq!(cfg(0, 8 * 1024).effective_max_sessions(), Ok(1024));
    }

    /// A generous budget is not licence to raise the cap. The operator asked for at most
    /// `max_sessions`, and a memory figure is a ceiling rather than a target.
    #[test]
    fn a_generous_budget_does_not_raise_the_cap() {
        assert_eq!(
            cfg(8, 1000 * per_session_mib()).effective_max_sessions(),
            Ok(8)
        );
    }

    /// A budget too small for one session refuses to start. Admitting one anyway would put
    /// the process over the figure the operator stated, which is the one outcome stating a
    /// budget was meant to rule out.
    #[test]
    fn a_budget_too_small_for_one_session_is_refused() {
        let err = cfg(1024, 1)
            .effective_max_sessions()
            .expect_err("a budget below one session's allowance must refuse");
        assert!(
            err.contains("below") && err.contains("growth"),
            "the message has to say which quantity was too small: {err}"
        );
    }
}
