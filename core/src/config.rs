use std::time::Duration;

/// Tunable parameters for a Phantom session / listener, exported across the
/// UniFFI boundary as a plain record.
///
/// NOTE: this is a stable FFI config surface, but the core does not yet read
/// most of these fields on the live data path — `PhantomConfig` is currently
/// re-exported and FFI-exported only. The `auto_fallback` / `fallback_*` /
/// `upgrade_delay` fields in particular describe the legacy multi-leg
/// fallback model; transport-leg fallback / aggregation was deliberately
/// dropped in favour of single-path connection migration, so those knobs are
/// presently inert. Treat the presets below as documented intent, not as
/// behaviour the core enforces today.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Debug, Clone)]
// New tunables must not break downstream construction. Build via `mobile()` /
// `server()` / `iot()` / `default()` then mutate the public fields.
#[non_exhaustive]
pub struct PhantomConfig {
    /// Interval between keep-alive pings
    pub keepalive_interval: Duration,
    /// Session inactivity timeout
    pub session_timeout: Duration,
    /// Maximum packet size (MTU)
    pub max_packet_size: u32,
    /// Send buffer size in packets
    pub send_buffer_size: u32,
    /// Receive buffer size in packets
    pub recv_buffer_size: u32,
    /// Maximum tickets in session cache
    pub session_cache_capacity: u32,
    /// Lifetime of a session ticket
    pub session_ticket_lifetime: Duration,
    /// Enable automatic transport fallback (legacy multi-leg model; inert —
    /// see the struct-level note).
    pub auto_fallback: bool,
    /// Packet loss percentage to trigger fallback (legacy multi-leg model; inert).
    pub fallback_loss_threshold: u8,
    /// Connection failures to trigger fallback (legacy multi-leg model; inert).
    pub fallback_failure_threshold: u32,
    /// Timeout for connection attempts
    pub connect_timeout: Duration,
    /// Delay before attempting to upgrade transport (legacy multi-leg model; inert).
    pub upgrade_delay: Duration,
}

impl Default for PhantomConfig {
    fn default() -> Self {
        Self::mobile()
    }
}

impl PhantomConfig {
    /// Optimized for mobile devices (LTE/Wi-Fi transitions, power saving)
    pub fn mobile() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(30),
            session_timeout: Duration::from_secs(3600),
            max_packet_size: 1350,
            send_buffer_size: 256,
            recv_buffer_size: 1024,
            session_cache_capacity: 32,
            session_ticket_lifetime: Duration::from_secs(86400),
            auto_fallback: true,
            fallback_loss_threshold: 15,
            fallback_failure_threshold: 3,
            connect_timeout: Duration::from_secs(5),
            upgrade_delay: Duration::from_secs(60),
        }
    }

    /// Optimized for servers (high throughput, static IP)
    pub fn server() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(60),
            session_timeout: Duration::from_secs(7200),
            max_packet_size: 1440,
            send_buffer_size: 2048,
            recv_buffer_size: 8192,
            session_cache_capacity: 1024,
            session_ticket_lifetime: Duration::from_secs(604800),
            auto_fallback: false,
            fallback_loss_threshold: 20,
            fallback_failure_threshold: 5,
            connect_timeout: Duration::from_secs(2),
            upgrade_delay: Duration::from_secs(300),
        }
    }

    /// Optimized for IoT devices (extremely low memory, slow networks)
    pub fn iot() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(120),
            session_timeout: Duration::from_secs(1800),
            max_packet_size: 512,
            send_buffer_size: 32,
            recv_buffer_size: 64,
            session_cache_capacity: 4,
            session_ticket_lifetime: Duration::from_secs(3600),
            auto_fallback: true,
            fallback_loss_threshold: 25,
            fallback_failure_threshold: 2,
            connect_timeout: Duration::from_secs(10),
            upgrade_delay: Duration::from_secs(600),
        }
    }
}
