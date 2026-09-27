use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use crate::errors::CoreError;

/// Tunable parameters for a Phantom session / listener, exported across the
/// UniFFI boundary as a plain record.
///
/// These five fields are actively consumed by the core:
/// - `keepalive_interval` → `LivenessConfig.keepalive_interval` (idle keep-alive PING interval)
/// - `session_timeout` → `LivenessConfig.idle_timeout` (Migrating→Dead reap window)
/// - `session_cache_capacity` → `SessionCache` max entries (server-only; client ignores)
/// - `session_ticket_lifetime` → `SessionCache` ticket lifetime (server-only; client ignores)
/// - `write_stall_timeout` → the write deadline of a stream transport — TCP or the
///   TLS-mimicry leg — that the entry point builds (PhantomUDP ignores it)
///
/// **Note:** `session_cache_capacity` and `session_ticket_lifetime` are consumed only on the
/// server path — by **both** listeners, [`PhantomListener`] over TCP and
/// [`PhantomUdpListener`] over PhantomUDP, which is the production
/// transport. Client `connect_*` entry points read `keepalive_interval`,
/// `session_timeout` and, over TCP, `write_stall_timeout` from this struct and
/// silently ignore the other two.
///
/// **Constructing one.** From Rust: `PhantomConfig::default()` — which is
/// `mobile()` — or one of the `server()` / `iot()` presets, then mutate the
/// fields. From a foreign binding there are **no presets**: UniFFI exports this
/// as a plain record with no associated functions and no field defaults, so a
/// Python, Swift or Kotlin caller builds the record itself and supplies every
/// field. The values `default()` uses are named on each field below so that
/// caller has something to copy. `#[non_exhaustive]` lets future tunables be
/// added without a breaking change to Rust callers; a foreign binding
/// regenerates instead.
///
/// [`PhantomListener`]: crate::api::listener::PhantomListener
/// [`PhantomUdpListener`]: crate::api::udp_listener::PhantomUdpListener
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PhantomConfig {
    /// Interval between idle keep-alive PINGs (maps to `LivenessConfig.keepalive_interval`).
    /// When the session is `Connected` and has been idle this long with nothing in flight,
    /// the data pump emits a small encrypted KEEPALIVE packet so a download-only path can
    /// detect a silently-dead peer via the same probe-timeout sweep.
    ///
    /// Defaults: 30 s (`mobile`, and so `default`), 60 s (`server`), 120 s (`iot`).
    pub keepalive_interval: Duration,
    /// Liveness reap window (maps to `LivenessConfig.idle_timeout`).
    ///
    /// **Note:** this is the `Migrating → Dead` timeout, not a general idle-disconnect timer.
    /// Keep-alive PINGs keep a `Connected` session alive indefinitely; this bounds how long
    /// a session that has gone unresponsive (entered `Migrating`) is retried before being
    /// declared `Dead`.
    ///
    /// Defaults: 3600 s (`mobile`), 7200 s (`server`), 1800 s (`iot`).
    pub session_timeout: Duration,
    /// Maximum 0-RTT resumption tickets the server keeps in memory.
    ///
    /// **SERVER-SIDE ONLY.** This field is consumed by the listeners — both
    /// [`PhantomListener`] over TCP and [`PhantomUdpListener`] over
    /// PhantomUDP, the production transport (via
    /// `PhantomListener::bind_with_config_bytes` or equivalent). When a
    /// [`PhantomConfig`] is passed to any `connect_*` client entry point, this field
    /// is silently ignored — the client does not own a session cache.
    ///
    /// Maps to [`SessionCache`] capacity; excess entries are evicted LRU.
    ///
    /// **Zero turns 0-RTT off.** A listener configured with `0` stores no tickets,
    /// so every resuming `ClientHello` finds nothing and completes as an ordinary
    /// 1-RTT handshake with `early_data_accepted == false`. That is the same
    /// posture `PhantomListener::set_early_data_enabled(false)` gives, reached from
    /// a config record instead of a method call — which is the only route a foreign
    /// binding has when it builds this record field by field. Until 0.3.1 the value
    /// was read as a bound to evict against rather than as a capacity, so a cache
    /// configured to hold nothing held one ticket and served 0-RTT out of it.
    ///
    /// Defaults: 32 (`mobile`), 1024 (`server`), 4 (`iot`). Consumed by both
    /// listeners, not only the TCP one.
    ///
    /// [`PhantomListener`]: crate::api::listener::PhantomListener
    /// [`SessionCache`]: crate::transport::session_cache::SessionCache
    /// [`PhantomUdpListener`]: crate::api::udp_listener::PhantomUdpListener
    pub session_cache_capacity: u32,
    /// Lifetime of 0-RTT resumption tickets on the server.
    ///
    /// **SERVER-SIDE ONLY.** This field is consumed by the listeners — both
    /// [`PhantomListener`] and [`PhantomUdpListener`]. When
    /// a [`PhantomConfig`] is passed to any `connect_*` client entry point, this field
    /// is silently ignored — the client does not own a session cache.
    ///
    /// Maps to [`SessionCache`] ticket lifetime.
    ///
    /// Defaults: 86400 s (`mobile`), 604800 s (`server`), 3600 s (`iot`).
    /// Consumed by both listeners, not only the TCP one.
    ///
    /// [`PhantomListener`]: crate::api::listener::PhantomListener
    /// [`SessionCache`]: crate::transport::session_cache::SessionCache
    /// [`PhantomUdpListener`]: crate::api::udp_listener::PhantomUdpListener
    pub session_ticket_lifetime: Duration,
    /// How long a write on a stream transport — TCP, or the TLS-mimicry leg — may go
    /// without the socket accepting a single byte before the session gives up on its
    /// peer. The write then fails with `CoreError::Timeout`, the connection is reset,
    /// and the session ends `Dead` with that cause.
    ///
    /// It bounds a peer that has **stopped** reading, not a slow one: every byte the
    /// socket accepts starts the clock again. But the socket reports progress coarsely.
    /// A write waiting on a full send buffer is woken only once a sizeable share of the
    /// buffer has drained — about a third of it on Linux — so on a slow path behind a
    /// large buffer the gaps between moments of progress are far longer than the byte
    /// rate suggests: a third of a 4 MiB buffer takes about 11 s to drain at 1 Mbit/s,
    /// and about 44 s at 256 kbit/s. Set this above the longest such gap the slowest
    /// expected path can produce, or a connection that is still moving is cut off.
    ///
    /// A longer deadline has a cost too. While a write waits, the session's pump waits
    /// with it: the session keeps its slot, and a `disconnect()` is carried out only
    /// once the write returns or the deadline passes. It must be at least one second —
    /// anything shorter gives up on nearly every write the socket could not take at
    /// once, which on a busy connection is almost every write — and the entry points
    /// that use it refuse a shorter one with `CoreError::ConfigError` before any I/O.
    ///
    /// That floor belongs to this field rather than to the deadline itself. A Rust
    /// caller who builds a transport of their own sets the deadline with
    /// `with_write_stall_timeout`, which takes any duration and hands back the
    /// transport rather than a `Result`, so the same sub-second value is refused
    /// here and accepted there. The difference is deliberate: a value in this record
    /// is one an operator supplied for connections the library builds on their
    /// behalf, out of their sight, while a duration handed straight to a transport is
    /// a choice its author made about that one transport — and making it is how the
    /// in-crate stall tests reach a stall in 250 ms instead of a second.
    ///
    /// Read by the TCP and TLS-mimicry listeners and by `connect_pinned_with_config`
    /// (and the mimicry connect that takes a config); ignored over PhantomUDP, whose
    /// sends never wait on the peer. An entry point that takes no `PhantomConfig` uses
    /// 30 s. A Rust caller that builds its own transport sets the deadline on that
    /// transport, and a config given to `SessionBuilder` does not change it.
    ///
    /// Defaults: 120 s (`mobile`, and so `default`), 30 s (`server`), 120 s (`iot`).
    pub write_stall_timeout: Duration,
}

impl Default for PhantomConfig {
    fn default() -> Self {
        Self::mobile()
    }
}

impl PhantomConfig {
    /// Preset for mobile devices (LTE/Wi-Fi transitions, power saving).
    ///
    /// Its write deadline is two minutes rather than thirty seconds. A TCP connection
    /// on a radio link rides out a dead spot on the kernel's retransmissions, and after
    /// an outage of a minute the retransmission back-off can leave the next attempt
    /// another minute away, so a write can go that long without progress on a path that
    /// is coming back. On a client the longer wait costs only the client itself.
    pub fn mobile() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(30),
            session_timeout: Duration::from_secs(3600),
            session_cache_capacity: 32,
            session_ticket_lifetime: Duration::from_secs(86400),
            write_stall_timeout: Duration::from_secs(120),
        }
    }

    /// Preset for servers (high throughput, static IP).
    ///
    /// Its write deadline is the default thirty seconds, the same horizon as the
    /// default liveness idle timeout: on a server a stalled write holds a session slot,
    /// and a client that has stopped reading should not be the one deciding when that
    /// slot comes free.
    pub fn server() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(60),
            session_timeout: Duration::from_secs(7200),
            session_cache_capacity: 1024,
            session_ticket_lifetime: Duration::from_secs(604800),
            write_stall_timeout: crate::transport::write_stall::DEFAULT_WRITE_STALL_TIMEOUT,
        }
    }

    /// Preset for IoT devices (low memory, slow networks).
    ///
    /// Its write deadline is two minutes, because slow links are where the socket's
    /// coarse progress reports leave the longest gaps between wake-ups (see
    /// [`write_stall_timeout`](Self::write_stall_timeout)).
    pub fn iot() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(120),
            session_timeout: Duration::from_secs(1800),
            session_cache_capacity: 4,
            session_ticket_lifetime: Duration::from_secs(3600),
            write_stall_timeout: Duration::from_secs(120),
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

    /// The write deadline for a stream transport built from this config, checked.
    ///
    /// Called by every entry point that builds a TCP or mimicry transport from a config,
    /// before it does any I/O, so a deadline too short to survive a busy send buffer is
    /// refused where it was supplied rather than discovered as a session that dies at
    /// the first full one.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn stream_write_stall_timeout(&self) -> Result<Duration, CoreError> {
        if self.write_stall_timeout < MIN_WRITE_STALL_TIMEOUT {
            return Err(CoreError::ConfigError(
                "PhantomConfig::write_stall_timeout must be at least one second".into(),
            ));
        }
        Ok(self.write_stall_timeout)
    }
}

/// The shortest write deadline a config may carry. A deadline shorter than this gives
/// up on writes that a busy but healthy connection routinely makes wait.
#[cfg(not(target_arch = "wasm32"))]
const MIN_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_preset_builds() {
        let cfg = PhantomConfig::mobile();
        assert_eq!(cfg.keepalive_interval, Duration::from_secs(30));
        assert_eq!(cfg.session_timeout, Duration::from_secs(3600));
        assert_eq!(cfg.write_stall_timeout, Duration::from_secs(120));
    }

    #[test]
    fn server_preset_builds() {
        let cfg = PhantomConfig::server();
        assert_eq!(cfg.session_cache_capacity, 1024);
        assert_eq!(cfg.write_stall_timeout, Duration::from_secs(30));
    }

    #[test]
    fn iot_preset_builds() {
        let cfg = PhantomConfig::iot();
        assert_eq!(cfg.session_cache_capacity, 4);
        assert_eq!(cfg.write_stall_timeout, Duration::from_secs(120));
    }

    /// The server preset's write deadline is the one an entry point without a config
    /// uses, and that one is the default liveness idle timeout; the preset's
    /// documentation leans on both.
    #[test]
    fn the_server_preset_uses_the_default_write_deadline() {
        assert_eq!(
            PhantomConfig::server().write_stall_timeout,
            crate::transport::write_stall::DEFAULT_WRITE_STALL_TIMEOUT
        );
        assert_eq!(
            PhantomConfig::server().write_stall_timeout,
            crate::transport::liveness::LivenessConfig::default().idle_timeout
        );
    }

    /// Every preset's deadline passes the check the entry points make, and zero or
    /// anything under a second does not.
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn a_zero_write_deadline_is_refused_and_the_presets_are_not() {
        for cfg in [
            PhantomConfig::mobile(),
            PhantomConfig::server(),
            PhantomConfig::iot(),
        ] {
            assert_eq!(
                cfg.stream_write_stall_timeout().ok(),
                Some(cfg.write_stall_timeout)
            );
        }
        for short in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_millis(999),
        ] {
            let cfg = PhantomConfig {
                write_stall_timeout: short,
                ..PhantomConfig::default()
            };
            assert!(
                matches!(
                    cfg.stream_write_stall_timeout(),
                    Err(CoreError::ConfigError(_))
                ),
                "{short:?} must be refused"
            );
        }
        let cfg = PhantomConfig {
            write_stall_timeout: MIN_WRITE_STALL_TIMEOUT,
            ..PhantomConfig::default()
        };
        assert_eq!(
            cfg.stream_write_stall_timeout().ok(),
            Some(MIN_WRITE_STALL_TIMEOUT)
        );
    }

    #[test]
    fn liveness_maps_correctly() {
        let cfg = PhantomConfig {
            keepalive_interval: Duration::from_secs(42),
            session_timeout: Duration::from_secs(999),
            session_cache_capacity: 10,
            session_ticket_lifetime: Duration::from_secs(3600),
            write_stall_timeout: Duration::from_secs(30),
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
            write_stall_timeout: Duration::from_secs(30),
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

    /// `session_cache_capacity: 0` must reach the cache as a disabled cache. This is
    /// the config-side half of the fix — the listeners build their cache through
    /// exactly this method, so a cache that stores nothing here is a listener that
    /// accepts no 0-RTT.
    #[test]
    fn a_zero_session_cache_capacity_disables_the_cache() {
        use crate::crypto::adaptive_crypto::CipherSuite;
        let cfg = PhantomConfig {
            session_cache_capacity: 0,
            ..PhantomConfig::default()
        };
        let mut cache = cfg.session_cache();
        assert!(cache.is_disabled(), "capacity 0 must disable the cache");
        cache.store([7u8; 32], &[8u8; 32], CipherSuite::Aes256Gcm);
        assert_eq!(cache.len(), 0, "a disabled cache must store no ticket");
        assert!(
            cache.peek(&[7u8; 32]).is_none(),
            "the resume gate must find nothing"
        );
        // Every preset ships a real cache; the disabled posture is opt-in.
        for preset in [
            PhantomConfig::mobile(),
            PhantomConfig::server(),
            PhantomConfig::iot(),
        ] {
            assert!(
                !preset.session_cache().is_disabled(),
                "preset with capacity {} must keep its cache",
                preset.session_cache_capacity
            );
        }
    }

    #[test]
    fn session_cache_expired_ticket() {
        use crate::crypto::adaptive_crypto::CipherSuite;
        let cfg = PhantomConfig {
            keepalive_interval: Duration::from_secs(30),
            session_timeout: Duration::from_secs(3600),
            session_cache_capacity: 64,
            session_ticket_lifetime: Duration::from_millis(1), // very short
            write_stall_timeout: Duration::from_secs(30),
        };
        let mut cache = cfg.session_cache();
        let secret = [0u8; 32];
        let sid = [42u8; 32];
        cache.store(sid, &secret, CipherSuite::Aes256Gcm);
        // Wait for ticket to expire
        std::thread::sleep(Duration::from_millis(5));
        // try_resume returns None for expired tickets
        assert!(
            cache.try_resume(&sid).is_none(),
            "expired ticket should not resume"
        );
    }
}
