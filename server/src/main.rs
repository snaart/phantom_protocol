//! Reference Phantom Core production server.
//!
//! Boot sequence:
//!
//! 1. Parse CLI / env into [`config::Config`].
//! 2. Initialize tracing (JSON or pretty per `--log-json`).
//! 3. Load-or-create the long-lived [`HybridSigningKey`].
//! 4. Log the verifying-key hex (operator captures this for client pinning).
//! 5. Bind the Phantom listener.
//! 6. Optionally bind the /metrics HTTP listener.
//! 7. Install SIGTERM / SIGINT handlers.
//! 8. Run the accept loop until shutdown is signaled.
//! 9. On shutdown: stop accepting, give in-flight tasks a short drain
//!    window, then exit 0.

mod config;
mod handler;
mod signing_key;
mod telemetry;

use anyhow::{Context, Result};
use clap::Parser;
use phantom_core::api::listener::PhantomListener;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::config::Config;
use crate::telemetry::{TelemetryCfg, TelemetryHandle};

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_DRAIN_GRACE: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::parse();

    // OTel must be installed BEFORE the tracing subscriber so the
    // `tracing-opentelemetry` layer has a tracer to bridge into. The
    // subscriber then composes the OTel layer alongside the fmt layer.
    let telemetry = TelemetryHandle::init(&TelemetryCfg {
        service_name: cfg.otel_service_name.clone(),
        otlp_endpoint: cfg.otlp_endpoint.clone(),
        trace_sample_ratio: cfg.otel_trace_sample_ratio,
    })
    .context("telemetry init")?;
    init_tracing(&cfg, &telemetry);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        bind = %cfg.bind,
        otlp_endpoint = %cfg.otlp_endpoint,
        signing_key_file = %cfg.signing_key_file.display(),
        "phantom-server starting"
    );

    // Generate or load the long-lived signing key BEFORE binding the
    // listener — if the key file is unreadable we'd rather fail loudly
    // here than after we're already accepting connections.
    let signing_key =
        signing_key::load_or_create(&cfg.signing_key_file).context("load_or_create signing key")?;
    let vk_hex = hex::encode(signing_key.verifying_key().to_bytes());

    // Thread the persisted signing key into the listener so the
    // verifying material clients pin is stable across restarts.
    // `bind_with_signing_key` constructs the listener's
    // `HandshakeServer` around our key — the listener's
    // `verifying_key_bytes()` is the SAME bytes we just logged from
    // disk, so we only need to surface one value to operators.
    let listener =
        PhantomListener::bind_with_signing_key(cfg.bind.to_string(), signing_key)
            .await
            .context("PhantomListener::bind_with_signing_key")?;
    debug_assert_eq!(
        hex::encode(listener.verifying_key_bytes()),
        vk_hex,
        "listener verifying key must equal the on-disk verifying key"
    );

    // Operator-facing pinning material. Emit at WARN so it survives
    // every reasonable log filter and isn't easy to miss in startup
    // output. Same value as both the on-disk verifying key and
    // `listener.verifying_key_bytes()`.
    tracing::warn!("server verifying key (pin this on clients): {}", vk_hex);
    tracing::info!(local_addr = %listener.local_addr(), "listener bound");

    let shutdown = install_shutdown_signal();

    // JoinSet tracks every spawned handler so we can give them a
    // bounded drain window on shutdown.
    let mut handlers: JoinSet<()> = JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            biased;

            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, stopping accept loop");
                break;
            }

            // Accept the next connection. The 30s timeout is a
            // defense-in-depth liveness check — the accept future
            // itself parks indefinitely on a quiet listener, and that
            // is fine; the timeout exists so a wedged listener can't
            // silently stop responding to the shutdown branch.
            outcome = tokio::time::timeout(ACCEPT_TIMEOUT, listener.accept()) => {
                match outcome {
                    Ok(Ok(accepted)) => {
                        let session = accepted.session();
                        handlers.spawn(async move {
                            handler::run_echo_handler(session).await;
                        });
                        // Reap finished handlers opportunistically to
                        // bound JoinSet growth on a busy server.
                        while let Some(res) = futures::FutureExt::now_or_never(handlers.join_next()).flatten() {
                            if let Err(e) = res {
                                tracing::warn!(error = %e, "handler task panicked");
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        // ConnectionClosed → shutdown was signalled
                        // concurrently from outside; just break.
                        if matches!(e, phantom_core::CoreError::ConnectionClosed) {
                            tracing::info!("listener reported shutdown");
                            break;
                        }
                        tracing::warn!(error = %e, "accept failed");
                    }
                    Err(_elapsed) => {
                        // Listener idle — loop back. No log; this is
                        // the normal quiet path.
                    }
                }
            }
        }
    }

    // Graceful shutdown: signal the listener, drain in-flight handlers
    // with a bounded grace window, then exit.
    listener.shutdown();
    tracing::info!(
        in_flight = handlers.len(),
        drain_grace_s = SHUTDOWN_DRAIN_GRACE.as_secs(),
        "draining in-flight sessions"
    );

    let drain = async {
        while let Some(res) = handlers.join_next().await {
            if let Err(e) = res {
                tracing::warn!(error = %e, "handler task panicked during drain");
            }
        }
    };
    if tokio::time::timeout(SHUTDOWN_DRAIN_GRACE, drain)
        .await
        .is_err()
    {
        tracing::warn!(
            remaining = handlers.len(),
            "drain timeout — aborting remaining handlers"
        );
        handlers.shutdown().await;
    }

    // Flush telemetry before exit so the last handshake counter / span
    // makes it out.
    telemetry.shutdown();
    tracing::info!("phantom-server shut down cleanly");
    Ok(())
}

fn init_tracing(cfg: &Config, telemetry: &TelemetryHandle) {
    let filter = EnvFilter::try_new(&cfg.log_filter)
        .unwrap_or_else(|_| EnvFilter::new("info,phantom_core=debug"));
    // OTel layer goes BEFORE fmt — fmt::layer doesn't forward `LookupSpan`
    // through, so OpenTelemetryLayer would not find the registry if
    // composed after it.
    let otel_layer = tracing_opentelemetry::layer().with_tracer(telemetry.tracer());
    if cfg.log_json {
        tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(fmt::layer().with_target(true))
            .init();
    }
}

/// Resolve on the first SIGTERM or SIGINT (Unix) / Ctrl-C (Windows).
async fn install_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler");
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGINT handler");
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("received SIGTERM"),
            _ = sigint.recv() => tracing::info!("received SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received Ctrl-C");
    }
}
