use std::time::Duration;

/// Tunable parameters for a Phantom session / listener, exported across the
/// UniFFI boundary as a plain record.
///
/// These four fields are actively consumed by the core:
/// - `keepalive_interval` → `LivenessConfig.keepalive_interval` (idle keep-alive PING interval)
/// - `session_timeout` → `LivenessConfig.idle_timeout` (Migrating→Dead reap window)
/// - `session_cache_capacity` → `SessionCache` max entries (server-only; client ignores)
/// - `session_ticket_lifetime` → `SessionCache` ticket lifetime (server-only; client ignores)
///
/// Build via `mobile()` / `server()` / `iot()` / `default()` then mutate fields;
/// `#[non_exhaustive]` lets future tunables be added without a breaking change.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PhantomConfig {
    /// Interval between idle keep-alive PINGs (maps to `LivenessConfig.keepalive_interval`).
    /// When the session is `Connected` and has been idle this long with nothing in flight,
    /// the data pump emits a small encrypted KEEPALIVE packet so a download-only path can
    /// detect a silently-dead peer via the same probe-timeout sweep.
    pub keepalive_interval: Duration,
    /// Liveness reap window (maps to `LivenessConfig.idle_timeout`).
    ///
    /// **Note:** this is the `Migrating → Dead` timeout, not a general idle-disconnect timer.
    /// Keep-alive PINGs keep a `Connected` session alive indefinitely; this bounds how long
    /// a session that has gone unresponsive (entered `Migrating`) is retried before being
    /// declared `Dead`.
    pub session_timeout: Duration,
    /// Maximum 0-RTT resumption tickets the server keeps in memory (server-only; ignored by
    /// clients). Maps to `SessionCache` capacity; excess entries are evicted LRU.
    pub session_cache_capacity: u32,
    /// Server-side resumption-ticket lifetime (server-only; ignored by clients). Maps to
    /// `SessionCache` ticket lifetime.
    pub session_ticket_lifetime: Duration,
}

impl Default for PhantomConfig {
    fn default() -> Self {
        Self::mobile()
    }
}

impl PhantomConfig {
    /// Preset for mobile devices (LTE/Wi-Fi transitions, power saving).
    pub fn mobile() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(30),
            session_timeout: Duration::from_secs(3600),
            session_cache_capacity: 32,
            session_ticket_lifetime: Duration::from_secs(86400),
        }
    }

    /// Preset for servers (high throughput, static IP).
    pub fn server() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(60),
            session_timeout: Duration::from_secs(7200),
            session_cache_capacity: 1024,
            session_ticket_lifetime: Duration::from_secs(604800),
        }
    }

    /// Preset for IoT devices (low memory, slow networks).
    pub fn iot() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(120),
            session_timeout: Duration::from_secs(1800),
            session_cache_capacity: 4,
            session_ticket_lifetime: Duration::from_secs(3600),
        }
    }

    /// Build a `LivenessConfig` from this config's liveness-relevant fields.
    pub(crate) fn liveness(&self) -> crate::transport::liveness::LivenessConfig {
        crate::transport::liveness::LivenessConfig {
            keepalive_interval: Some(self.keepalive_interval),
            idle_timeout: self.session_timeout,
            ..crate::transport::liveness::LivenessConfig::default()
        }
    }

    /// Build a `SessionCache` sized and timed per this config.
    pub(crate) fn session_cache(&self) -> crate::transport::session_cache::SessionCache {
        crate::transport::session_cache::SessionCache::with_capacity(
            self.session_cache_capacity as usize,
            self.session_ticket_lifetime,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_preset_builds() {
        let cfg = PhantomConfig::mobile();
        assert_eq!(cfg.keepalive_interval, Duration::from_secs(30));
        assert_eq!(cfg.session_timeout, Duration::from_secs(3600));
    }

    #[test]
    fn server_preset_builds() {
        let cfg = PhantomConfig::server();
        assert_eq!(cfg.session_cache_capacity, 1024);
    }

    #[test]
    fn iot_preset_builds() {
        let cfg = PhantomConfig::iot();
        assert_eq!(cfg.session_cache_capacity, 4);
    }

    #[test]
    fn liveness_maps_correctly() {
        let cfg = PhantomConfig {
            keepalive_interval: Duration::from_secs(42),
            session_timeout: Duration::from_secs(999),
            session_cache_capacity: 10,
            session_ticket_lifetime: Duration::from_secs(3600),
        };
        let live = cfg.liveness();
        assert_eq!(live.keepalive_interval, Some(Duration::from_secs(42)));
        assert_eq!(live.idle_timeout, Duration::from_secs(999));
        // Other fields should be the default values
        let default_live = crate::transport::liveness::LivenessConfig::default();
        assert_eq!(live.min_pto, default_live.min_pto);
        assert_eq!(live.path_down_ptos, default_live.path_down_ptos);
    }

    #[test]
    fn session_cache_honors_capacity() {
        use crate::crypto::adaptive_crypto::CipherSuite;
        let cfg = PhantomConfig {
            keepalive_interval: Duration::from_secs(30),
            session_timeout: Duration::from_secs(3600),
            session_cache_capacity: 2,
            session_ticket_lifetime: Duration::from_secs(3600),
        };
        let mut cache = cfg.session_cache();
        // Store 3 tickets; capacity=2 so the first should be evicted LRU
        let secret = [0u8; 32];
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let s3 = [3u8; 32];
        cache.store(s1, &secret, CipherSuite::Aes256Gcm);
        cache.store(s2, &secret, CipherSuite::Aes256Gcm);
        cache.store(s3, &secret, CipherSuite::Aes256Gcm);
        // s1 should have been evicted (LRU); s2 and s3 should still be present
        assert!(cache.try_resume(&s1).is_none(), "s1 should be evicted");
        assert!(cache.try_resume(&s3).is_some(), "s3 should be present");
    }

    #[test]
    fn session_cache_expired_ticket() {
        use crate::crypto::adaptive_crypto::CipherSuite;
        let cfg = PhantomConfig {
            keepalive_interval: Duration::from_secs(30),
            session_timeout: Duration::from_secs(3600),
            session_cache_capacity: 64,
            session_ticket_lifetime: Duration::from_millis(1), // very short
        };
        let mut cache = cfg.session_cache();
        let secret = [0u8; 32];
        let sid = [42u8; 32];
        cache.store(sid, &secret, CipherSuite::Aes256Gcm);
        // Wait for ticket to expire
        std::thread::sleep(Duration::from_millis(5));
        // try_resume returns None for expired tickets
        assert!(cache.try_resume(&sid).is_none(), "expired ticket should not resume");
    }
}
