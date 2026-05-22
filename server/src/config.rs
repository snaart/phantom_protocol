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
    about = "Phantom Core reference server"
)]
pub struct Config {
    /// Bind address for the Phantom transport (TCP).
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

    /// Trace sampling ratio (0.0 — 1.0). Default 1% baseline; bump to 1.0
    /// when investigating an incident, or set to 0 to disable trace export.
    #[arg(long, env = "OTEL_TRACES_SAMPLER_ARG", default_value = "0.01")]
    pub otel_trace_sample_ratio: f64,

    /// Service name reported via OTel Resource. Defaults to the binary
    /// name; override per-instance for multi-tenant deployments.
    #[arg(long, env = "OTEL_SERVICE_NAME", default_value = "phantom-server")]
    pub otel_service_name: String,

    /// Output structured JSON logs (default: pretty when stdout is a TTY).
    #[arg(long, env = "PHANTOM_LOG_JSON")]
    pub log_json: bool,

    /// Tracing filter (default: info,phantom_core=debug).
    #[arg(long, env = "RUST_LOG", default_value = "info,phantom_core=debug")]
    pub log_filter: String,
}
