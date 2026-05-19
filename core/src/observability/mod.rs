//! Phantom Core observability subsystem.
//!
//! Replaces the Phase 4.5 hand-rolled metrics module (`transport::metrics`).
//! Lock-free hot-path atomics for per-packet recording plus opt-in
//! OpenTelemetry instruments (metrics + traces) gated behind the
//! `telemetry-otel` Cargo feature.
//!
//! See `docs/observability/refactor-plan.md` for the full design and
//! atomic-commit rollout. This file is the public module surface; concrete
//! types live in the submodules below.
//!
//! ## Status (Phase 8 rollout)
//!
//! Step 2 — scaffold only. The `Observability` facade is a placeholder; the
//! hot-path atomics, OTel instruments, observable bridge, and recording APIs
//! land in subsequent atomic commits.

pub mod config;

pub use config::{HistogramConfig, ObservabilityConfig, ObservabilityConfigBuilder};

use std::sync::Arc;

/// Public observability facade.
///
/// Wraps the lock-free atomic counters (always present) and the
/// feature-gated OpenTelemetry instrument holder. Recording sites in
/// `transport`, `api`, and `crypto` will call methods on this struct via an
/// `Arc<Observability>` borrowed from `PhantomListener` / `PhantomSession`.
///
/// In step 2 of the rollout this struct only holds the configuration; the
/// recording surface and the inner subsystems are wired in by subsequent
/// commits (see the rollout table in `docs/observability/refactor-plan.md`).
#[derive(Debug, Default)]
pub struct Observability {
    config: ObservabilityConfig,
}

impl Observability {
    /// Construct a new observability handle.
    ///
    /// Returns an `Arc` because the handle is shared between recording sites
    /// (in `Session`, `Listener`, handshake code paths) and the OTel
    /// observable callbacks registered in a later step.
    pub fn new(config: ObservabilityConfig) -> Arc<Self> {
        Arc::new(Self { config })
    }

    /// Borrow the captured configuration.
    pub fn config(&self) -> &ObservabilityConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_observability_has_default_config() {
        let obs = Observability::default();
        assert_eq!(obs.config().namespace.as_ref(), "phantom");
    }

    #[test]
    fn new_returns_arc_with_provided_config() {
        let cfg = ObservabilityConfig::builder().namespace("myapp").build();
        let obs = Observability::new(cfg);
        assert_eq!(obs.config().namespace.as_ref(), "myapp");
        // Cloning the Arc preserves identity.
        let obs2 = obs.clone();
        assert_eq!(obs2.config().namespace.as_ref(), "myapp");
    }
}
