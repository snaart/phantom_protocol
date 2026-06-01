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
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::config::Config;
use crate::telemetry::{TelemetryCfg, TelemetryHandle};

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_DRAIN_GRACE: Duration = Duration::from_secs(10);

/// Caps concurrent sessions per source IP so one peer cannot monopolise the
/// global session pool. Cloneable (cheap `Arc`); a cap of 0 disables it.
#[derive(Clone)]
struct PerIpLimiter {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

impl PerIpLimiter {
    fn new(max_per_ip: usize) -> Self {
        Self {
            counts: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
        }
    }

    /// Admit a session from `ip`. Returns an RAII guard that decrements the
    /// count on drop, or `None` if `ip` is already at the cap. `max_per_ip == 0`
    /// disables the limit (always admits, no tracking).
    fn admit(&self, ip: IpAddr) -> Option<PerIpGuard> {
        if self.max_per_ip == 0 {
            return Some(PerIpGuard {
                limiter: self.clone(),
                ip,
                counted: false,
            });
        }
        // Poison recovery rather than panic: the critical section is a single
        // map op, but a panic elsewhere must not wedge admission.
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let n = counts.entry(ip).or_insert(0);
        if *n >= self.max_per_ip {
            return None;
        }
        *n += 1;
        Some(PerIpGuard {
            limiter: self.clone(),
            ip,
            counted: true,
        })
    }
}

/// Decrements the per-IP session count when the handler task finishes.
struct PerIpGuard {
    limiter: PerIpLimiter,
    ip: IpAddr,
    counted: bool,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = counts.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.ip); // keep the map from growing unbounded
            }
        }
    }
}

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

    // Admission control: a global session cap (backpressure — stop accepting
    // when full rather than exhausting fds/memory) plus a per-IP cap so one
    // source can't monopolise the pool. `max_sessions == 0` → unbounded.
    let session_slots = Arc::new(Semaphore::new(if cfg.max_sessions == 0 {
        Semaphore::MAX_PERMITS
    } else {
        cfg.max_sessions
    }));
    let per_ip = PerIpLimiter::new(cfg.max_sessions_per_ip);
    tracing::info!(
        max_sessions = cfg.max_sessions,
        max_sessions_per_ip = cfg.max_sessions_per_ip,
        "session admission control active"
    );

    // JoinSet tracks every spawned handler so we can give them a
    // bounded drain window on shutdown.
    let mut handlers: JoinSet<()> = JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        // Acquire a global session slot BEFORE accepting — backpressure: at
        // capacity the loop parks here (raced with shutdown) instead of doing
        // handshake work for a session we couldn't keep. The permit moves into
        // the handler and is released when the session ends.
        let session_slot = tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, stopping accept loop");
                break;
            }
            permit = session_slots.clone().acquire_owned() => match permit {
                Ok(p) => p,
                // The semaphore is never closed; treat the impossible error as stop.
                Err(_) => break,
            },
        };

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
                        let peer_ip = accepted.peer_addr().ip();
                        match per_ip.admit(peer_ip) {
                            Some(ip_guard) => {
                                let session = accepted.session();
                                handlers.spawn(async move {
                                    // Both guards live for the session's lifetime:
                                    // the global slot frees and the per-IP count
                                    // drops when the handler returns.
                                    let _session_slot = session_slot;
                                    let _ip_guard = ip_guard;
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
                            None => {
                                // Per-IP cap hit. Dropping `accepted` at the end
                                // of this arm closes the freshly-handshaked
                                // session; `session_slot` drops with the loop
                                // iteration, releasing the unused global slot.
                                tracing::warn!(
                                    peer = %peer_ip,
                                    max_sessions_per_ip = cfg.max_sessions_per_ip,
                                    "per-IP session cap reached; rejecting connection"
                                );
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        // ConnectionClosed → shutdown was signalled
                        // concurrently from outside; just break. The unused
                        // `session_slot` drops here, releasing the slot.
                        if matches!(e, phantom_core::CoreError::ConnectionClosed) {
                            tracing::info!("listener reported shutdown");
                            break;
                        }
                        tracing::warn!(error = %e, "accept failed");
                    }
                    Err(_elapsed) => {
                        // Listener idle — loop back. The unused `session_slot`
                        // drops here, releasing the reserved slot.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(b: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, b))
    }

    #[test]
    fn per_ip_limiter_caps_rejects_and_releases() {
        let lim = PerIpLimiter::new(2);
        let a = ip(1);

        let g1 = lim.admit(a).expect("1st under cap");
        let g2 = lim.admit(a).expect("2nd under cap");
        assert!(lim.admit(a).is_none(), "3rd exceeds the per-IP cap");

        // A different source IP is independent.
        let _other = lim.admit(ip(2)).expect("other IP unaffected");

        // Releasing a slot frees one for that IP.
        drop(g1);
        let g3 = lim.admit(a).expect("re-admitted after a release");

        drop(g2);
        drop(g3);
        // Fully drained: the entry is removed so the map can't grow unbounded.
        assert!(lim
            .counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&a)
            .is_none());
    }

    #[test]
    fn per_ip_limiter_zero_disables_and_does_not_track() {
        let lim = PerIpLimiter::new(0);
        let a = ip(1);
        let _g1 = lim.admit(a).expect("admit");
        let _g2 = lim.admit(a).expect("admit");
        let _g3 = lim.admit(a).expect("admit");
        let counts = lim.counts.lock().unwrap_or_else(|e| e.into_inner());
        assert!(counts.is_empty(), "a disabled cap tracks nothing");
    }
}
