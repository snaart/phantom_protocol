//! Command-line + environment configuration for `phantom-server`.
//!
//! Every flag has both a CLI form (e.g. `--bind`) and an environment
//! fallback (e.g. `PHANTOM_BIND`). The env fallback is what
//! systemd/docker/kubernetes deployments use; the CLI form is for
//! local development.

use clap::Parser;
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
    /// `LimitNOFILE` and per-session memory (~512 KiB) — see
    /// `docs/operations/deployment.md`. `0` means unbounded (not recommended).
    #[arg(long, env = "PHANTOM_MAX_SESSIONS", default_value = "1024")]
    pub max_sessions: usize,

    /// Maximum concurrent sessions from a single source IP. A peer already at
    /// this many active sessions has further connections rejected (closed right
    /// after the handshake) so one source cannot monopolise the global pool.
    /// `0` disables the per-IP cap.
    #[arg(long, env = "PHANTOM_MAX_SESSIONS_PER_IP", default_value = "64")]
    pub max_sessions_per_ip: usize,
}
