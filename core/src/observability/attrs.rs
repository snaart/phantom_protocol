//! Typed attribute values for OpenTelemetry instruments.
//!
//! Every dimension the library slices a metric by is a small `Copy` enum
//! here with a `const fn as_str()` returning a `&'static str`. Recording
//! sites pass the enum; the instrument layer builds the `KeyValue` list.
//!
//! Why typed enums rather than free-form strings: the enum *is* the
//! cardinality contract. A metric can only be labeled by a value that
//! exists as an enum variant, so the unbounded-cardinality offenders
//! (`peer_ip`, `session_id`, `stream_id`) simply cannot be passed — there
//! is no enum that admits them. See `docs/observability/refactor-plan.md`
//! §4 "Cardinality contract".
//!
//! Performance: the labeled instruments these feed (`record_handshake`,
//! `record_replay_rejected`, …) are all cold / low-frequency event paths,
//! so the `KeyValue` list is built per-call. The genuinely hot path
//! (per-packet counts) does NOT go through here — it uses lock-free
//! atomics drained by `ObservableCounter` callbacks (`bridge.rs`), which
//! build their `KeyValue`s once per SDK collection cycle, not per packet.
//! Per-call attribute construction on the cold paths is not worth
//! interning away.
//!
//! `as_str()` is `const` and the enums are feature-independent, so this
//! module compiles identically with or without `telemetry-otel` — call
//! sites need no `#[cfg]` guards.

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
        LegType::Udp => "udp",
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

/// Wire-protocol version label for handshake metrics. Pinned — the protocol
/// is not negotiated (one wire version), so this is always `Current`. The
/// variant is kept (rather than dropping the metric attribute) so dashboards
/// retain a stable `version` dimension across a future, deliberate bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    /// The sole, pinned wire protocol.
    Current,
}

impl ProtocolVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "v1",
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
        assert_eq!(leg_str(LegType::Udp), "udp");
    }

    #[test]
    fn protocol_version_strings() {
        assert_eq!(ProtocolVersion::Current.as_str(), "v1");
    }
}
