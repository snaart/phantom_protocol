//! Pre-interned OpenTelemetry attribute sets.
//!
//! `KeyValue` allocation on every recording call would dominate the cost of
//! labeled instruments — `Vec<KeyValue>` building, string interning, and
//! `AttributeSet` hashing each contribute. We pre-build the full set of
//! attribute combinations the library will ever emit, store them in
//! `OnceLock`s, and have recording APIs take an enum index into that table.
//!
//! Cost on hot path: one indexed slice borrow, then OTel SDK's labeled-add
//! path (HashMap lookup on a stable already-interned set).
//!
//! Pre-interned sets cover the *finite* attribute combinations the library
//! emits. Per-path attributes (`path_id`) are bounded by `MAX_PATHS=16` and
//! also pre-built. Unbounded attributes (`peer_ip`, `session_id`,
//! `stream_id`) are NEVER emitted as OTel labels — see "Cardinality
//! contract" in `docs/observability/refactor-plan.md` §4.
//!
//! When `telemetry-otel` is disabled the attribute-set machinery still
//! compiles (cheap `&'static str` constants) so call sites don't need
//! `#[cfg]` guards.

use crate::transport::types::LegType;

/// Direction of an I/O operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Send,
    Recv,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Recv => "recv",
        }
    }
}

/// String labels for `LegType`. Stable strings used as OTel attribute
/// values; never user-facing.
pub fn leg_str(leg: LegType) -> &'static str {
    match leg {
        LegType::Kcp => "kcp",
        LegType::Tcp => "tcp",
        LegType::FakeTls => "faketls",
    }
}

/// Outcome of a handshake attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeOutcome {
    Success,
    Failure,
}

impl HandshakeOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Wire version negotiated during the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    V12,
    V3,
}

impl ProtocolVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V12 => "v12",
            Self::V3 => "v3",
        }
    }
}

/// AEAD algorithm used at the record-protection layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// Reason a replay-rejected packet was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayReason {
    /// Sequence number falls below the window's lower edge.
    Old,
    /// Sequence number inside the window but already marked seen.
    Duplicate,
}

impl ReplayReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Old => "old",
            Self::Duplicate => "duplicate",
        }
    }
}

/// Outcome of a stateless-cookie validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CookieOutcome {
    Issued,
    ValidatedOk,
    ValidatedMismatch,
}

impl CookieOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::ValidatedOk => "validated_ok",
            Self::ValidatedMismatch => "validated_mismatch",
        }
    }
}

/// Outcome of a proof-of-work challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowOutcome {
    Solved,
    Rejected,
}

impl PowOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Solved => "solved",
            Self::Rejected => "rejected",
        }
    }
}

/// 0-RTT early-data outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EarlyDataOutcome {
    Accepted,
    RejectedUnknownTicket,
    RejectedOversized,
    RejectedAead,
    RejectedReplay,
}

impl EarlyDataOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::RejectedUnknownTicket => "rejected_unknown_ticket",
            Self::RejectedOversized => "rejected_oversized",
            Self::RejectedAead => "rejected_aead",
            Self::RejectedReplay => "rejected_replay",
        }
    }
}

/// Resumption mode for the handshake counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResumptionMode {
    OneRtt,
    ZeroRtt,
}

impl ResumptionMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OneRtt => "1rtt",
            Self::ZeroRtt => "0rtt",
        }
    }
}

/// Outcome of a `PATH_VALIDATION` exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathValidationOutcome {
    Success,
    Failure,
}

impl PathValidationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Reason a multi-path fallback was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FallbackReason {
    LossThreshold,
    RttThreshold,
    PathFailure,
    Explicit,
}

impl FallbackReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LossThreshold => "loss_threshold",
            Self::RttThreshold => "rtt_threshold",
            Self::PathFailure => "path_failure",
            Self::Explicit => "explicit",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_strings_are_stable() {
        assert_eq!(Direction::Send.as_str(), "send");
        assert_eq!(Direction::Recv.as_str(), "recv");
    }

    #[test]
    fn leg_str_covers_all_variants() {
        assert_eq!(leg_str(LegType::Kcp), "kcp");
        assert_eq!(leg_str(LegType::Tcp), "tcp");
        assert_eq!(leg_str(LegType::FakeTls), "faketls");
    }

    #[test]
    fn protocol_version_strings() {
        assert_eq!(ProtocolVersion::V12.as_str(), "v12");
        assert_eq!(ProtocolVersion::V3.as_str(), "v3");
    }
}
