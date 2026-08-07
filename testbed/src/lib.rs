//! Real-network (WAN) test harness for the Phantom protocol.
//!
//! Two binaries share this library:
//!
//! - `phantom-testd` — the daemon. Binds every network-testable leg (PhantomUDP,
//!   Phantom-over-TCP, mimic-TLS), a QUIC reference leg, and the raw TCP/UDP
//!   controls — two echoes plus a one-way downstream source — and records
//!   server-side statistics.
//! - `phantom-probe` — the client. Drives a scenario matrix across those legs
//!   and writes raw per-operation samples.
//!
//! Three kinds of leg, and confusing them is how a result gets misread: the
//! Phantom legs are the protocol under test, the raw legs are controls carrying
//! no protocol at all, and the QUIC leg is a *reference* — a mature
//! implementation of the same class, on the same path, in the same run.
//!
//! Everything here is a consumer of the published `phantom-protocol` API. The
//! harness never reaches into protocol internals, so a result it produces is a
//! statement about the shipped surface rather than about a private path.
//!
//! ## Why a separate crate
//!
//! The repository's automated tests all run over loopback or an in-memory
//! transport, where RTT is microseconds, nothing reorders, no NAT exists, and
//! the path MTU is 65535. That regime cannot exercise the RTO timer, the
//! bandwidth estimator, real migration, or path-MTU behaviour. This crate is
//! the instrument for the regime that can.

/// The build script's rule for choosing between the commit a deployment names
/// and the one git reports, compiled here so `cargo test` can execute it.
///
/// Build scripts are not test targets: nothing in `cargo test` runs `build.rs`,
/// which is how the daemon shipped a run artifact reading `unknown` without a
/// red test anywhere. `build.rs` includes the same file textually, so the rule
/// under test is the rule that runs.
#[cfg(test)]
#[path = "../build_identity.rs"]
mod build_identity;

pub mod clock;
pub mod downlink;
pub mod framing;
pub mod pacing;
pub mod probe;
pub mod proto;
pub mod quic;
pub mod report;
pub mod stats;
pub mod sysinfo;
pub mod testd;
