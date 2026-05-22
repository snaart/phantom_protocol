//! Bridge between lock-free hot-path atomics and OTel observable instruments.
//!
//! Approach: register observable callbacks at instrument-construction time.
//! On every collection cycle (driven by the embedder's `PeriodicReader` —
//! default 10s) the OTel SDK invokes our callback, which reads the atomic
//! counters with `Ordering::Relaxed` and reports per-leg observations with
//! the correct `direction` / `leg` labels.
//!
//! No background task of our own — the periodicity belongs to the SDK
//! reader. This means one fewer lifecycle (no spawn / no JoinHandle to
//! manage on shutdown) and the period stays configurable via the OTel
//! standard env (`OTEL_METRIC_EXPORT_INTERVAL`).
//!
//! When `telemetry-otel` is OFF this module compiles to nothing — the
//! observable bridge is a pure OTel construct.

#[cfg(feature = "telemetry-otel")]
pub(crate) use otel_on::register_observables;

#[cfg(not(feature = "telemetry-otel"))]
#[inline(always)]
pub(crate) fn register_observables(
    _atomics: &std::sync::Arc<crate::observability::atomics::HotPathAtomics>,
    _config: &crate::observability::config::ObservabilityConfig,
) {
}

#[cfg(feature = "telemetry-otel")]
mod otel_on {
    use crate::observability::atomics::{HotPathAtomics, DIR_RECV, DIR_SEND, MAX_PATHS};
    use crate::observability::attrs::{leg_str, Direction};
    use crate::observability::config::ObservabilityConfig;
    use crate::transport::types::LegType;
    use opentelemetry::KeyValue;
    use std::sync::Arc;

    /// Register all observable instruments backed by `HotPathAtomics`.
    ///
    /// Call once at `Observability::new` time. The closures capture a
    /// strong `Arc<HotPathAtomics>` so the atomics outlive every
    /// collection cycle even if the `Observability` handle on the public
    /// side is dropped.
    pub(crate) fn register_observables(atomics: &Arc<HotPathAtomics>, config: &ObservabilityConfig) {
        let meter = opentelemetry::global::meter("phantom_core");
        let ns = config.namespace.as_ref();

        // phantom.session.packets — ObservableCounter, labeled (direction, leg)
        let packets_atomics = atomics.clone();
        let _ = meter
            .u64_observable_counter(format!("{ns}.session.packets"))
            .with_description("Packets transmitted/received, sliced by direction and leg")
            .with_callback(move |observer| {
                for (dir_idx, dir) in [(DIR_SEND, Direction::Send), (DIR_RECV, Direction::Recv)] {
                    for leg in [LegType::Kcp, LegType::Tcp, LegType::FakeTls] {
                        let v = packets_atomics.packets_per_leg(dir_idx, leg);
                        observer.observe(
                            v,
                            &[
                                KeyValue::new("direction", dir.as_str()),
                                KeyValue::new("leg", leg_str(leg)),
                            ],
                        );
                    }
                }
            })
            .build();

        // phantom.session.io — ObservableCounter, labeled (direction, leg)
        let bytes_atomics = atomics.clone();
        let _ = meter
            .u64_observable_counter(format!("{ns}.session.io"))
            .with_description("Bytes transmitted/received, sliced by direction and leg")
            .with_unit("By")
            .with_callback(move |observer| {
                for (dir_idx, dir) in [(DIR_SEND, Direction::Send), (DIR_RECV, Direction::Recv)] {
                    for leg in [LegType::Kcp, LegType::Tcp, LegType::FakeTls] {
                        let v = bytes_atomics.bytes_per_leg(dir_idx, leg);
                        observer.observe(
                            v,
                            &[
                                KeyValue::new("direction", dir.as_str()),
                                KeyValue::new("leg", leg_str(leg)),
                            ],
                        );
                    }
                }
            })
            .build();

        // phantom.crypto.encrypt.duration_sum / _count — ObservableCounter pair
        let enc_atomics = atomics.clone();
        let _ = meter
            .u64_observable_counter(format!("{ns}.crypto.encrypt.duration_sum"))
            .with_description("Cumulative AEAD encrypt time (ns)")
            .with_unit("ns")
            .with_callback(move |observer| {
                observer.observe(enc_atomics.encrypt_sum_ns(), &[]);
            })
            .build();
        let enc_count_atomics = atomics.clone();
        let _ = meter
            .u64_observable_counter(format!("{ns}.crypto.encrypt.invocations"))
            .with_description("AEAD encrypt invocation count")
            .with_callback(move |observer| {
                observer.observe(enc_count_atomics.encrypt_count(), &[]);
            })
            .build();
        let dec_atomics = atomics.clone();
        let _ = meter
            .u64_observable_counter(format!("{ns}.crypto.decrypt.duration_sum"))
            .with_description("Cumulative AEAD decrypt time (ns)")
            .with_unit("ns")
            .with_callback(move |observer| {
                observer.observe(dec_atomics.decrypt_sum_ns(), &[]);
            })
            .build();
        let dec_count_atomics = atomics.clone();
        let _ = meter
            .u64_observable_counter(format!("{ns}.crypto.decrypt.invocations"))
            .with_description("AEAD decrypt invocation count")
            .with_callback(move |observer| {
                observer.observe(dec_count_atomics.decrypt_count(), &[]);
            })
            .build();

        // phantom.path.rtt — ObservableGauge per path_id
        let rtt_atomics = atomics.clone();
        let _ = meter
            .u64_observable_gauge(format!("{ns}.path.rtt"))
            .with_description("Latest observed RTT per path")
            .with_unit("us")
            .with_callback(move |observer| {
                for path_id in 0..MAX_PATHS as u8 {
                    let v = rtt_atomics.rtt_us(path_id);
                    if v > 0 {
                        observer.observe(v, &[KeyValue::new("path_id", path_id as i64)]);
                    }
                }
            })
            .build();
    }
}
